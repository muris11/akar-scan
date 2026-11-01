from __future__ import annotations

from ..models import Finding, Page, Severity
from ..utils import clip, parse_set_cookie
from .base import Check


class CookiesCheck(Check):
    id = "cookies"
    name = "Cookie flags"
    description = "Secure/HttpOnly/SameSite attributes on cookies."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.set_cookies:
            return
        seen: set[str] = ctx.state.setdefault("cookie_seen", set())
        on_https = page.url.startswith("https://")

        for raw in page.set_cookies:
            name, _value, attrs = parse_set_cookie(raw)
            if not name or name in seen:
                continue
            seen.add(name)

            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = attrs.get("samesite", "").lower()
            evidence = clip(raw, 180)

            if on_https and not secure:
                ctx.add(
                    Finding(
                        id="cookie-missing-secure",
                        title=f"Cookie '{name}' missing Secure flag",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        param=name,
                        detail="The cookie can be sent over plaintext connections.",
                        evidence=evidence,
                        remediation="Add the Secure attribute.",
                    )
                )
            if not httponly:
                ctx.add(
                    Finding(
                        id="cookie-missing-httponly",
                        title=f"Cookie '{name}' missing HttpOnly flag",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        param=name,
                        detail="JavaScript can read this cookie (XSS impact amplifier).",
                        evidence=evidence,
                        remediation="Add the HttpOnly attribute.",
                    )
                )
            if not samesite:
                ctx.add(
                    Finding(
                        id="cookie-missing-samesite",
                        title=f"Cookie '{name}' missing SameSite attribute",
                        severity=Severity.LOW,
                        url=page.url,
                        param=name,
                        detail="Browser defaults may allow cross-site sending.",
                        evidence=evidence,
                        remediation="Set SameSite=Lax (or Strict) unless cross-site use is required.",
                    )
                )
            elif samesite == "none" and not secure:
                ctx.add(
                    Finding(
                        id="cookie-samesite-none-insecure",
                        title=f"Cookie '{name}' uses SameSite=None without Secure",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        param=name,
                        detail="Browsers reject this combination; behavior is inconsistent.",
                        evidence=evidence,
                        remediation="SameSite=None requires the Secure attribute.",
                    )
                )
            if not on_https:
                ctx.add(
                    Finding(
                        id="cookie-plaintext",
                        title=f"Cookie '{name}' issued over plaintext HTTP",
                        severity=Severity.LOW,
                        url=page.url,
                        param=name,
                        detail="The cookie is visible to anyone on the network path.",
                        evidence=evidence,
                        remediation="Serve the site entirely over HTTPS.",
                    )
                )
