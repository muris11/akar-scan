from __future__ import annotations

import asyncio
import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from .models import Form, Input, Page
from .utils import canonical_url, is_asset, is_same_site, origin_of

log = logging.getLogger("akar.crawl")

QUERY_LINK_RE = re.compile(r"""["'](/(?:[a-zA-Z0-9_\-./?=&%~+@#$]{2,120}))["']""")
LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.I)


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self.base = ""
        self.meta_refresh = ""
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "area" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "base" and a.get("href") and not self.base:
            self.base = a["href"]
        elif tag in ("script", "iframe", "embed", "source", "video", "audio", "frame") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "object" and a.get("data"):
            self.links.append(a["data"])
        elif tag == "img":
            for key in ("src", "data-src", "data-lazy-src", "data-original"):
                if a.get(key):
                    self.links.append(a[key])
            if a.get("srcset"):
                self.links.extend(x.split()[0] for x in a["srcset"].split(",") if x.strip())
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            m = re.search(r"url\s*=\s*(.+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = m.group(1).strip(" '\"")
        elif tag == "form":
            self._form = Form(action=a.get("action", ""), method=(a.get("method") or "GET").upper())
            self.forms.append(self._form)
        elif self._form is not None and tag in ("input", "textarea", "select"):
            name = a.get("name") or a.get("id")
            if name:
                self._form.inputs.append(
                    Input(name=name, type=(a.get("type") or "text").lower(), value=a.get("value") or "")
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def parse_html(body: str) -> LinkParser:
    parser = LinkParser()
    try:
        parser.feed(body[:1_000_000])
        parser.close()
    except Exception:  # noqa: BLE001
        pass
    return parser


class Crawler:
    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.args = ctx.args
        self.q: asyncio.Queue = asyncio.Queue()
        self.seen: set[str] = set()
        self.fetched = 0

    async def run(self) -> None:
        origin = origin_of(self.ctx.base_url)
        self._enqueue(self.ctx.base_url, 0)
        await self._load_robots(origin)
        workers = [
            asyncio.create_task(self.worker()) for _ in range(max(1, min(self.args.threads, 32)))
        ]
        await self.q.join()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        self.ctx.progress(f"crawled {self.fetched} urls, {len(self.ctx.pages)} html pages")

    async def _load_robots(self, origin: str) -> None:
        ctx = self.ctx
        robots = await ctx.client.get(origin + "/robots.txt")
        if robots.status == 200 and "html" not in (robots.content_type or "").lower():
            ctx.robots = robots
            sitemaps: list[str] = []
            current_ua_star = False
            for line in robots.body.splitlines()[:800]:
                stripped = line.strip()
                low = stripped.lower()
                if low.startswith("user-agent:"):
                    current_ua_star = "*" in stripped
                elif low.startswith("disallow:"):
                    path = stripped.split(":", 1)[1].strip()
                    if path:
                        ctx.robots_paths.add(path)
                        if self.args.robots and current_ua_star:
                            self._enqueue(origin + path, 0)
                elif low.startswith("sitemap:"):
                    sitemaps.append(stripped.split(":", 1)[1].strip())
        else:
            sitemaps = []

        if not sitemaps:
            sitemaps.append(origin + "/sitemap.xml")
        sm = await ctx.client.get(sitemaps[0])
        if sm.status == 200 and "<loc>" in sm.body[:50000].lower():
            locs = LOC_RE.findall(sm.body)
            ctx.state["sitemap_count"] = len(locs)
            for loc in locs[:1000]:
                self._enqueue(loc.strip(), 0)

    async def worker(self) -> None:
        while True:
            item = await self.q.get()
            try:
                await self._handle(*item)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.debug("crawl error %s: %s", item[0], exc)
            finally:
                self.q.task_done()

    def _enqueue(self, url: str, depth: int, robots: bool = False) -> None:
        if not url or url.startswith(("mailto:", "javascript:", "data:", "tel:", "about:", "ftp:", "#")):
            return
        if not url.startswith("http"):
            return
        if self.fetched >= self.args.max_pages:
            return
        key = canonical_url(url)
        if key in self.seen:
            return
        if len(self.seen) > self.args.max_pages * 5 + 300:
            return
        self.seen.add(key)
        self.q.put_nowait((url, depth, robots))

    async def _handle(self, url: str, depth: int, robots: bool) -> None:
        if depth > self.args.depth:
            return
        ctx = self.ctx
        page = await ctx.client.get(url)
        self.fetched += 1
        if self.fetched % 10 == 0:
            self.ctx.progress(f"crawled {self.fetched} urls / {len(ctx.pages)} pages")
        page.depth = depth
        page.from_robots = robots
        if not page.status or page.error or not page.is_html:
            return
        ctx.pages.append(page)

        parsed = parse_html(page.body)
        page.forms = parsed.forms
        effective_base = urljoin(page.url, parsed.base) if parsed.base else page.url
        for form in page.forms:
            form.action = urljoin(effective_base, form.action) if form.action else page.url

        links = list(parsed.links)
        if parsed.meta_refresh:
            links.append(parsed.meta_refresh)
        if self.args.parse_js:
            links.extend(QUERY_LINK_RE.findall(page.body))

        for raw in links:
            if depth + 1 > self.args.depth:
                break
            absolute = urljoin(effective_base, raw)
            if not is_same_site(ctx.base_url, absolute, self.args.subdomains):
                continue
            if is_asset(absolute) and not (self.args.parse_js and absolute.endswith(".js")):
                continue
            self._enqueue(absolute, depth + 1)
