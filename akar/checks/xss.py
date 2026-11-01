from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..models import Finding, Form, Page, Severity
from .base import Check
from .common import form_is_sensitive, spend, testable_params


class XssCheck(Check):
    id = "xss"
    name = "Reflected input (XSS probe)"
    description = "Canary-based reflection detection in query params and GET forms."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.ok:
            return
        canary = f"akx{secrets.token_hex(4)}"
        raw_marker = f"<{canary}>"
        encoded_markers = ("&lt;" + canary, "\\u003c" + canary, "\\x3c" + canary,
                           "%3c" + canary, "\\u003C" + canary)

        tested: set[str] = ctx.state.setdefault("xss_params_tested", set())

        for param in testable_params(page, limit=6):
            key = f"{page.url}|{param}"
            if key in tested or not spend(ctx):
                continue
            tested.add(key)
            payload = f'">{raw_marker}'
            resp = await ctx.client.get(_inject(page.url, param, payload))
            if resp.error:
                continue
            if raw_marker in resp.body:
                ctx.add(Finding(
                    id="xss-reflected",
                    title=f"Unencoded reflection of '{param}' (potential reflected XSS)",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    param=param,
                    detail="The parameter is reflected verbatim into the HTML body without encoding.",
                    evidence=_snippet(resp.body, raw_marker),
                    remediation="Context-encode output (HTML entity / JS string encoding) and deploy a CSP.",
                ))
                break
            if any(marker in resp.body for marker in encoded_markers):
                ctx.add(Finding(
                    id="xss-reflected-encoded",
                    title=f"Reflection of '{param}' with output encoding",
                    severity=Severity.INFO,
                    url=page.url,
                    param=param,
                    detail="The parameter is reflected but appears encoded; no XSS demonstrated.",
                    evidence=_snippet(resp.body, canary),
                    remediation="Keep output encoding consistent across every sink.",
                ))
                break

        # GET forms
        for form in page.forms[:4]:
            if (form.method or "GET").upper() != "GET":
                continue
            if form_is_sensitive(form) or form.has_file():
                continue
            if not spend(ctx):
                return
            if await self._test_form(ctx, page, form, raw_marker, encoded_markers):
                return

    async def _test_form(self, ctx, page: Page, form: Form, raw_marker: str, encoded_markers) -> bool:
        fields = [i for i in form.inputs if i.name and i.type in ("text", "hidden", "search", "url", "email")]
        if not fields:
            return False
        for field in fields[:3]:
            if not spend(ctx):
                return False
            query = []
            for i in form.inputs:
                if not i.name:
                    continue
                query.append((i.name, raw_marker if i.name == field.name else (i.value or "")))

            target = form.action + ("&" if "?" in form.action else "?") + urlencode(query)
            resp = await ctx.client.get(target)
            if resp.error:
                continue
            if raw_marker in resp.body:
                ctx.add(Finding(
                    id="xss-reflected-form",
                    title=f"Unencoded reflection via form field '{field.name}'",
                    severity=Severity.MEDIUM,
                    url=form.action,
                    param=field.name,
                    detail="A GET form field is reflected unencoded into the response.",
                    evidence=_snippet(resp.body, raw_marker),
                    remediation="Context-encode output and add a CSP.",
                ))
                return True
        return False


def _inject(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    out, replaced = [], False
    for key, val in pairs:
        if key == param and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, val))
    if not replaced:
        out.append((param, value))
    return f"{parts.scheme}://{parts.netloc}{parts.path}?{urlencode(out, doseq=True)}"


def _snippet(body: str, marker: str, size: int = 110) -> str:
    idx = body.find(marker)
    if idx < 0:
        return body[: size * 2]
    start = max(0, idx - size)
    return re.sub(r"\s+", " ", body[start : idx + len(marker) + size])
