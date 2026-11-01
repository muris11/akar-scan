from __future__ import annotations

import re

from ..models import Finding, Page, Severity
from ..utils import origin_of
from .base import Check
from .common import looks_like_baseline

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
SENSITIVE_COMMENT_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|todo|fixme|hack|xxx|temp|temporary|"
    r"internal|localhost|127\.0\.0\.1|hack|note:|author|@[\w.-]+\.\w{2,})",
    re.I,
)
PATH_COMMENT_RE = re.compile(r"([A-Za-z]:\\\\|/(?:home|var|www|Users|opt|srv)/)[\w\\/. -]{3,}")
STACK_RE = re.compile(
    r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|"
    r"System\.\w+Exception|Fatal error:|Warning: \w+\(|Stack trace:|"
    r"#0 \{[\w]|org\.\w+\.\w+Exception",
    re.I,
)
DIRLISTING_RE = re.compile(
    r"<(?:title|h1)>\s*(?:index of|directory listing for|directories of)\s*/?", re.I
)
INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
SENSITIVE_ROBOTS_RE = re.compile(
    r"(admin|backup|private|secret|api|dev|staging|\.git|config|upload|includes|"
    r"old|test|debug|console|db|sql|dump|cms|tmp|temp|internal)",
    re.I,
)
SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=(\S+)", re.I)


class InfoLeakCheck(Check):
    id = "info-leak"
    name = "Information disclosure"
    description = "Server banners, stack traces, directory listings, comments, source maps, robots."

    async def on_page(self, ctx, page: Page) -> None:
        if page.url == ctx.base_url:
            self._headers(ctx, page)
            self._robots(ctx, page)
        self._comments(ctx, page)
        self._stack_traces(ctx, page)
        self._directory_listing(ctx, page)
        self._internal_ips(ctx, page)

    async def run(self, ctx) -> None:
        await self._source_maps(ctx)

    # -- headers -----------------------------------------------------------
    def _headers(self, ctx, page: Page) -> None:
        server = page.header("server")
        if server and re.search(r"\d+\.\d+", server):
            ctx.add(Finding(
                id="leak-server-version",
                title="Server version disclosed",
                severity=Severity.INFO,
                url=page.url,
                detail="Version information in the Server header aids targeted exploits.",
                evidence=f"Server: {server}",
                remediation="Suppress version tokens in the Server banner.",
            ))
        powered = page.header("x-powered-by")
        if powered:
            ctx.add(Finding(
                id="leak-powered-by",
                title="X-Powered-By header disclosed",
                severity=Severity.INFO,
                url=page.url,
                evidence=f"X-Powered-By: {powered}",
                remediation="Remove X-Powered-By (e.g. expose_powering=False / X-Powered-By removal).",
            ))
        if page.header("x-aspnet-version") or page.header("x-aspnetmvc-version"):
            ctx.add(Finding(
                id="leak-aspnet-version",
                title="ASP.NET version header disclosed",
                severity=Severity.INFO,
                url=page.url,
                evidence=f"X-AspNet-Version: {page.header('x-aspnet-version')}",
                remediation="Remove version headers in web.config (removeServerHeader / enableVersionHeader=false).",
            ))

    # -- robots ------------------------------------------------------------
    def _robots(self, ctx, page: Page) -> None:
        if ctx.robots is None or not ctx.robots_paths:
            return
        sensitive = sorted({p for p in ctx.robots_paths if SENSITIVE_ROBOTS_RE.search(p)})
        if not sensitive:
            return
        ctx.add(Finding(
            id="leak-robots-sensitive",
            title="robots.txt hides sensitive-looking paths",
            severity=Severity.LOW,
            url=origin_of(ctx.base_url) + "/robots.txt",
            detail="Disallowed paths advertise admin/backup/internal locations.",
            evidence=", ".join(sensitive[:20]),
            remediation="Rely on access control instead of robots.txt for sensitive areas.",
        ))
        count = ctx.state.get("sitemap_count", 0)
        if count:
            ctx.add(Finding(
                id="leak-sitemap",
                title=f"Sitemap exposes {count} URLs",
                severity=Severity.INFO,
                url=origin_of(ctx.base_url) + "/sitemap.xml",
                evidence=f"{count} URLs",
                remediation="Ensure unpublished/test URLs are not reachable.",
            ))

    # -- per page ----------------------------------------------------------
    def _comments(self, ctx, page: Page) -> None:
        seen: set[str] = ctx.state.setdefault("comment_seen", set())
        for match in COMMENT_RE.finditer(page.body[:400_000]):
            text = match.group(1).strip()
            if len(text) < 15 or len(text) > 600:
                continue
            interesting = bool(SENSITIVE_COMMENT_RE.search(text) or PATH_COMMENT_RE.search(text))
            if not interesting:
                continue
            cleaned = re.sub(r"\s+", " ", text)[:220]
            if cleaned in seen:
                continue
            seen.add(cleaned)
            ctx.add(Finding(
                id="leak-comment",
                title="Sensitive HTML comment in source",
                severity=Severity.LOW,
                url=page.url,
                detail="Comment leaks internal notes, paths, or credentials-adjacent information.",
                evidence=cleaned,
                remediation="Strip comments from production templates; never commit secrets as notes.",
            ))

    def _stack_traces(self, ctx, page: Page) -> None:
        if looks_like_baseline(ctx, page):
            return
        match = STACK_RE.search(page.body[:400_000])
        if not match:
            return
        ctx.add(Finding(
            id="leak-stack-trace",
            title="Stack trace / verbose error in response",
            severity=Severity.MEDIUM,
            url=page.url,
            detail="Error output exposes internals (framework, files, versions).",
            evidence=re.sub(r"\s+", " ", page.body[max(0, match.start() - 60): match.end() + 160])[:260],
            remediation="Return generic errors in production; log details server-side only.",
        ))

    def _directory_listing(self, ctx, page: Page) -> None:
        if not DIRLISTING_RE.search(page.body[:2000]):
            return
        if ctx.baseline and DIRLISTING_RE.search(ctx.baseline.body[:2000]) and page.url == ctx.base_url:
            return
        ctx.add(Finding(
            id="leak-directory-listing",
            title="Directory listing enabled",
            severity=Severity.MEDIUM,
            url=page.url,
            detail="Browsable indexes reveal file names, backups and directory structure.",
            evidence=_title(page.body),
            remediation="Disable autoindex / directory indexes (autoindex off; Options -Indexes).",
        ))

    def _internal_ips(self, ctx, page: Page) -> None:
        matches = set(INTERNAL_IP_RE.findall(page.body[:400_000]))
        if not matches:
            return
        ctx.add(Finding(
            id="leak-internal-ip",
            title="Internal IP address in response body",
            severity=Severity.LOW,
            url=page.url,
            detail="Internal addressing reveals network topology and may indicate misdirected configs.",
            evidence=", ".join(sorted(matches)[:6]),
            remediation="Avoid emitting internal IPs in client-facing responses.",
        ))

    # -- source maps -------------------------------------------------------
    async def _source_maps(self, ctx) -> None:
        candidates: list[str] = []
        seen: set[str] = set()
        for page in ctx.pages:
            for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", page.body[:200_000], re.I):
                full = src if src.startswith("http") else None
                if full is None:
                    from urllib.parse import urljoin

                    full = urljoin(page.url, src)
                from ..utils import is_same_site, origin_of as _origin  # noqa: F401

                if not is_same_site(ctx.base_url, full):
                    continue
                if full in seen:
                    continue
                seen.add(full)
                candidates.append(full)
            if len(candidates) >= 12:
                break

        for script_url in candidates[:12]:
            page = await ctx.client.head(script_url + ".map", follow=False)
            if page.status != 200 or looks_like_baseline(ctx, page):
                continue
            ct = (page.content_type or "").lower()
            length = int(page.header("content-length", "0") or "0")
            if "json" not in ct and length == 0:
                # some servers do not answer HEAD properly; verify with a ranged GET
                page = await ctx.client.get(script_url + ".map", follow=False)
                if page.status != 200 or not page.body.lstrip().startswith("{"):
                    continue
                length = len(page.body)
            ctx.add(Finding(
                id="leak-sourcemap",
                title="Source map exposed",
                severity=Severity.MEDIUM,
                url=script_url + ".map",
                detail="Compiled JS ships with original source (paths, comments, internals).",
                evidence=f"content-type={ct or '-'}, length={length}",
                remediation="Do not deploy .map files to production, or restrict them by auth.",
            ))
            if len(ctx.findings) > 0 and sum(1 for f in ctx.findings if f.id == "leak-sourcemap") >= 8:
                return


def _title(body: str) -> str:
    match = re.search(r"<title>(.*?)</title>", body[:4000], re.I | re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""
