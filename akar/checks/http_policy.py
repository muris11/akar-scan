from __future__ import annotations

from ..models import Finding, Severity
from .base import Check

PROBE_HOST = "akarhost.invalid"
HOST_HEADERS = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Host"]


class HttpPolicyCheck(Check):
    id = "http-policy"
    name = "HTTP policy & Host header"
    description = "HTTPS-to-HTTP downgrade, Host header injection, cache-poisoning signals."

    async def run(self, ctx) -> None:
        base = ctx.base_url
        if base.startswith("https://"):
            await self._check_downgrade(ctx, base)
        await self._check_host_header(ctx, base)

    async def _check_downgrade(self, ctx, base: str) -> None:
        http_url = "http://" + base[8:]
        resp = await ctx.client.get(http_url, follow=False)
        if not resp.status or resp.status >= 500:
            return
        hsts = ""
        base_page = next((p for p in ctx.pages if p.url == ctx.base_url), None)
        if base_page:
            hsts = base_page.header("strict-transport-security")
        severity = Severity.MEDIUM if not hsts else Severity.LOW
        ctx.add(Finding(
            id="policy-http-downgrade",
            title="Content available over plaintext HTTP",
            severity=severity,
            url=http_url,
            detail=(
                "The same site responds over HTTP"
                + (", and without HSTS a browser can be downgrade-attacked." if not hsts else
                   ", but HSTS limits the exposure window.")
            ),
            evidence=f"HTTP status={resp.status}",
            remediation="Redirect HTTP to HTTPS at the edge and enable HSTS with includeSubDomains.",
        ))

    async def _check_host_header(self, ctx, base: str) -> None:
        seen: set[str] = ctx.state.setdefault("host_header_tested", set())
        for header in HOST_HEADERS:
            if header in seen:
                continue
            seen.add(header)
            resp = await ctx.client.get(base, headers={"Host": PROBE_HOST, header: PROBE_HOST})
            if resp.error or PROBE_HOST not in resp.body:
                continue
            idx = resp.body.find(PROBE_HOST)
            snippet = resp.body[max(0, idx - 80): idx + 90]
            is_link_context = any(
                marker in resp.body[max(0, idx - 300): idx + 100].lower()
                for marker in ("http://", "https://", "href=", "action=", "src=", "content=")
            )
            ctx.add(Finding(
                id="policy-host-header-injection",
                title=f"Host header reflection via {header}",
                severity=Severity.MEDIUM if is_link_context else Severity.LOW,
                url=base,
                detail=(
                    "The supplied host value is reflected into the response"
                    + (" and appears inside URL/link context (cache poisoning / password-reset "
                       "poisoning vector)." if is_link_context else ".")
                ),
                evidence=_clean(snippet),
                remediation="Validate the Host header against a server allowlist; use relative URLs.",
            ))
            break


def _clean(text: str) -> str:
    import re

    return re.sub(r"\s+", " ", text).strip()[:220]
