from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .models import Page
from .utils import clip, host_of, parse_cookie_header

log = logging.getLogger("akar.http")

DEFAULT_UA = "AkarScan/1.0 (+security-scanner)"
RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}


class HttpClient:
    def __init__(self, args: Any):
        self.args = args
        headers: dict[str, str] = {
            "User-Agent": getattr(args, "user_agent", None) or DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        for raw in getattr(args, "header", None) or []:
            if ":" in raw:
                key, value = raw.split(":", 1)
                headers[key.strip()] = value.strip()

        cookies = parse_cookie_header(getattr(args, "cookie", "") or "")

        http2 = False
        if not getattr(args, "no_http2", False):
            try:
                import h2  # noqa: F401

                http2 = True
            except ImportError:
                http2 = False

        auth = None
        if getattr(args, "auth", None) and ":" in args.auth:
            user, password = args.auth.split(":", 1)
            auth = httpx.BasicAuth(user, password)

        timeout = httpx.Timeout(args.timeout, connect=min(args.timeout, 10.0))
        limits = httpx.Limits(
            max_connections=max(20, args.threads + 10),
            max_keepalive_connections=20,
        )

        self.client = httpx.AsyncClient(
            headers=headers,
            cookies=cookies or None,
            proxy=getattr(args, "proxy", None) or None,
            verify=not getattr(args, "insecure", False),
            timeout=timeout,
            follow_redirects=True,
            max_redirects=10,
            http2=http2,
            limits=limits,
            auth=auth,
        )
        self.stats: dict[str, int] = {"requests": 0, "errors": 0, "bytes": 0}
        self.rate = float(getattr(args, "rate", 0) or 0)
        self._next_at: dict[str, float] = {}

    async def _throttle(self, host: str) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        wait = self._next_at.get(host, 0.0) - now
        if wait > 0:
            await asyncio.sleep(wait)
        self._next_at[host] = time.monotonic() + 1.0 / self.rate

    async def request(self, method: str, url: str, **kwargs: Any) -> Page:
        method = method.upper()
        follow = kwargs.pop("follow", True)
        retries = int(kwargs.pop("retries", 2))
        if method not in RETRY_METHODS:
            retries = 0
        last_error = ""
        for attempt in range(retries + 1):
            await self._throttle(host_of(url))
            try:
                t0 = time.perf_counter()
                resp = await self.client.request(method, url, follow_redirects=follow, **kwargs)
                elapsed = time.perf_counter() - t0
                self.stats["requests"] += 1
                body = resp.text
                if len(body) > 2_000_000:
                    body = body[:2_000_000]
                self.stats["bytes"] += len(body)
                return Page(
                    url=str(resp.url),
                    status=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    set_cookies=resp.headers.get_list("set-cookie"),
                    body=body,
                    content_type=resp.headers.get("content-type", ""),
                    elapsed=elapsed,
                    redirects=[str(h.url) for h in resp.history],
                )
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < retries:
                    await asyncio.sleep(0.4 * (attempt + 1))
                    continue
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                break
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
                break
        self.stats["errors"] += 1
        log.debug("request failed %s %s -> %s", method, url, last_error)
        return Page(url=url, error=clip(last_error, 200))

    async def get(self, url: str, **kwargs: Any) -> Page:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Page:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> Page:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> Page:
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self) -> None:
        await self.client.aclose()
