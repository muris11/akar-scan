from __future__ import annotations

from ..models import Finding, Page, Severity
from .base import Check
from .common import form_has_token, form_is_sensitive


class CsrfCheck(Check):
    id = "csrf"
    name = "CSRF protection"
    description = "State-changing forms without anti-CSRF tokens; credentials over GET."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.forms:
            return
        session_cookies = [
            raw.split("=", 1)[0].strip()
            for raw in page.set_cookies
            if "samesite" not in raw.lower()
        ]

        for form in page.forms:
            method = (form.method or "GET").upper()
            if method not in ("POST", "PUT", "DELETE", "PATCH"):
                # credentials submitted over GET leak via history/logs/referrers
                if method == "GET" and any(
                    i.type == "password" for i in form.inputs
                ):
                    ctx.add(Finding(
                        id="csrf-password-get",
                        title="Password submitted via GET",
                        severity=Severity.MEDIUM,
                        url=form.action,
                        detail="Credentials in a GET form land in server logs, browser history and Referer headers.",
                        evidence=f"fields: {', '.join(form.names[:8])}",
                        remediation="Submit credentials via POST over HTTPS only.",
                    ))
                continue

            if form_is_sensitive(form) and not form.names:
                continue
            if form.has_file():
                continue

            if form_has_token(form):
                continue

            field_key = ",".join(sorted(form.names))[:80]
            if ctx.has("csrf-missing-token", form.action, field_key):
                continue

            detail = "The form performs a state-changing action without an anti-CSRF token."
            if session_cookies:
                detail += f" Cookies lacking SameSite on this page: {', '.join(session_cookies[:4])}."

            ctx.add(Finding(
                id="csrf-missing-token",
                title=f"Form without CSRF token ({method})",
                severity=Severity.LOW,
                url=form.action,
                param=field_key,
                detail=detail,
                evidence=f"fields: {', '.join(form.names[:10]) or '(none)'}",
                remediation="Add a per-session anti-CSRF token and set SameSite cookies.",
            ))
