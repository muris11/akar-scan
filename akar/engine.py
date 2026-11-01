from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from secrets import token_hex
from typing import Any, Callable
from urllib.parse import urlsplit

from .checks import build_checks
from .crawl import Crawler
from .fingerprint import fingerprint
from .http import HttpClient
from .models import Finding, Page, Severity
from .utils import normalize_url, origin_of

log = logging.getLogger("akar.engine")


@dataclass
class Context:
    args: Any
    client: HttpClient
    base_url: str = ""
    findings: list[Finding] = field(default_factory=list)
    pages: list[Page] = field(default_factory=list)
    robots: Page | None = None
    robots_paths: set[str] = field(default_factory=set)
    tech: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    tls: dict[str, Any] = field(default_factory=dict)
    subdomains: dict[str, list[str]] = field(default_factory=dict)
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    baseline: Page | None = None
    state: dict[str, Any] = field(default_factory=dict)
    started: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self._seen: set[tuple] = set()
        self._progress: Callable[[str], None] | None = getattr(self.args, "progress", None)

    def add(self, finding: Finding) -> None:
        if finding.key() in self._seen:
            return
        self._seen.add(finding.key())
        self.findings.append(finding)

    def has(self, check_id: str, url: str = "", param: str = "") -> bool:
        return (check_id, url, param) in self._seen

    def note_technology(self, category: str, name: str) -> None:
        if name and name not in self.tech[category]:
            self.tech[category].append(name)

    def progress(self, message: str) -> None:
        if self._progress:
            self._progress(message)

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    @property
    def duration(self) -> float:
        return time.time() - self.started


async def _make_baseline(ctx: Context) -> Page:
    origin = origin_of(ctx.base_url)
    path = urlsplit(ctx.base_url).path or "/"
    parent = path.rsplit("/", 1)[0] or ""
    return await ctx.client.get(f"{origin}{parent}/akar404-{token_hex(5)}.html")


def _select_sample(ctx: Context) -> list[Page]:
    limit = max(1, ctx.args.max_test_pages)
    html_pages = [p for p in ctx.pages if p.ok and p.is_html]
    with_query = [p for p in html_pages if "?" in p.url]
    without_query = [p for p in html_pages if "?" not in p.url]
    return (with_query + without_query)[:limit]


async def run_scan(args: Any) -> Context:
    ctx = Context(args=args, client=HttpClient(args))
    skip_set = set(args.skip or [])

    def enabled(check_id: str) -> bool:
        return check_id not in skip_set

    target = normalize_url(args.url)
    page = await ctx.client.get(target)
    if not page.status:
        alt = ("http://" + target[8:]) if target.startswith("https://") else ("https://" + target[7:])
        alt_page = await ctx.client.get(alt)
        if alt_page.status:
            page = alt_page
    if not page.status:
        await ctx.client.close()
        raise RuntimeError(f"target unreachable: {page.error or 'no response'}")

    ctx.base_url = page.url
    page.depth = 0
    ctx.pages.append(page)
    ctx.progress(f"target {ctx.base_url} [{page.status}]")
    fingerprint(ctx, page)

    # crawl (also loads robots.txt and sitemap)
    await Crawler(ctx).run()

    ctx.baseline = await _make_baseline(ctx)

    checks = build_checks(args.only, args.skip)
    sample = _select_sample(ctx)
    log.info("running %d checks over %d sampled pages", len(checks), len(sample))

    for check in checks:
        for pg in sample:
            try:
                await check.on_page(ctx, pg)
            except Exception as exc:  # noqa: BLE001
                log.debug("on_page %s %s: %s", check.id, pg.url, exc)

    for check in checks:
        try:
            await check.run(ctx)
        except Exception as exc:  # noqa: BLE001
            log.debug("run %s: %s", check.id, exc)

    if args.subdomains and enabled("subdomains"):
        from .recon import subdomains as subdomains_mod

        await subdomains_mod.enumerate(ctx)

    if args.ports and enabled("ports"):
        from .recon import ports as ports_mod

        await ports_mod.scan(ctx)

    ctx.findings.sort(key=lambda f: (-int(f.severity), f.id, f.url))
    await ctx.client.close()
    return ctx
