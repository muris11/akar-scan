from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Finding, Page, Severity
from .base import Check
from .common import spend, testable_params

REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "redirect_url", "redir", "return", "return_to",
    "returnto", "return_url", "continue", "dest", "destination", "target", "rurl", "goto",
    "out", "view", "image_url", "checkout_url", "file", "path", "page", "forward", "callback",
    "data", "reference", "site", "domain", "feed", "host", "qurl", "u", "uri", "success",
    "cancel", "login", "returnTo", "redirect_to", "r", "jump", "link", "to", "from",
]

PAYLOADS = [
    "https://akarredirect.invalid",
    "//akarredirect.invalid",
    "///akarredirect.invalid",
    "%2f%2fakarredirect.invalid",
    "https:%2f%2fakarredirect.invalid",
    "/\\akarredirect.invalid",
]

EVIL_HOST = "akarredirect.invalid"


class OpenRedirectCheck(Check):
    id = "open-redirect"
    name = "Open redirect"
    description = "Unvalidated redirect parameters usable for phishing chains."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.ok:
            return
        tested_params: set[str] = ctx.state.setdefault("redirect_params_tested", set())

        for param in testable_params(page, limit=6):
            if param in tested_params or not spend(ctx):
                continue
            tested_params.add(param)
            if await self._test(ctx, page.url, param):
                return

    async def run(self, ctx) -> None:
        # also try common parameter names on the base URL even if not present
        tested: set[str] = ctx.state.setdefault("redirect_params_tested", set())
        for param in REDIRECT_PARAMS:
            if param in tested or len(tested) > 40 or not spend(ctx):
                break
            tested.add(param)
            if await self._test(ctx, ctx.base_url, param):
                return

    async def _test(self, ctx, url: str, param: str) -> bool:
        from ..utils import build_url

        for payload in PAYLOADS:
            if not spend(ctx):
                return False
            target = build_url(url, param, payload)
            resp = await ctx.client.get(target, follow=False)
            if resp.error:
                continue

            location = resp.header("location", "")
            if 300 <= resp.status < 400 and location:
                try:
                    loc_host = (urlsplit(location).hostname or "").lower()
                except ValueError:
                    loc_host = ""
                if loc_host == EVIL_HOST or loc_host.endswith("." + EVIL_HOST):
                    self._report(ctx, url, param, payload, resp, f"Location: {location}")
                    return True
                # relative redirect that still contains the raw payload host in a tricky form
                if EVIL_HOST in location:
                    self._report(ctx, url, param, payload, resp, f"Location: {location}")
                    return True

            if resp.status == 200 and EVIL_HOST in resp.body:
                lowered = resp.body.lower()
                idx = lowered.find(EVIL_HOST)
                window = lowered[max(0, idx - 200) : idx + 100]
                if any(marker in window for marker in ("location", "window.location", "url=", "content=")):
                    self._report(ctx, url, param, payload, resp, "client-side redirect reflection")
                    return True
        return False

    def _report(self, ctx, url: str, param: str, payload: str, resp: Page, evidence: str) -> None:
        ctx.add(
            Finding(
                id="open-redirect",
                title=f"Open redirect via '{param}'",
                severity=Severity.HIGH,
                url=url,
                param=param,
                detail=(
                    "The parameter controls the redirect destination without validating the "
                    "target host; usable for phishing and OAuth token theft chains."
                ),
                evidence=f"payload={payload}; {evidence}",
                remediation="Allowlist redirect targets or map them to internal identifiers; reject absolute foreign URLs.",
            )
        )
