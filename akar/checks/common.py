from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..models import Form, Page

SKIP_PARAM_RE = re.compile(r"^(csrf|xsrf|utm_|fbclid|gclid|gclsrc)", re.I)
SENSITIVE_FORM_RE = re.compile(
    r"(login|log-?in|signin|sign-?in|auth|register|signup|sign-?up|password|reset|"
    r"logout|delete|payment|checkout|transfer)",
    re.I,
)
TOKEN_INPUT_RE = re.compile(r"(csrf|xsrf|token|nonce|authenticity|verification)", re.I)


def testable_params(page: Page, limit: int = 10) -> list[str]:
    """Query parameter names on the page worth injecting payloads into."""
    names: list[str] = []
    for key, _ in parse_qsl(urlsplit(page.url).query, keep_blank_values=True):
        if SKIP_PARAM_RE.match(key):
            continue
        if key not in names:
            names.append(key)
    return names[:limit]


def looks_like_baseline(ctx, page: Page) -> bool:
    """True when a 200/404 response is just the site's fallback page (SPA rewrite)."""
    base = getattr(ctx, "baseline", None)
    if base is None or not base.status:
        return False
    from ..utils import similarity

    if page.status == base.status and abs(len(page.body) - len(base.body)) < 30:
        return True
    if page.status == base.status and similarity(page.body, base.body) > 0.97:
        return True
    return False


def spend(ctx, cost: int = 1) -> bool:
    """Consume from the active-testing request budget."""
    used = int(ctx.state.get("test_requests", 0))
    budget = int(ctx.args.max_tests)
    if used >= budget:
        return False
    ctx.state["test_requests"] = used + cost
    return True


def form_is_sensitive(form: Form) -> bool:
    return bool(SENSITIVE_FORM_RE.search(form.action))


def form_has_token(form: Form) -> bool:
    return any(TOKEN_INPUT_RE.search(inp.name or "") for inp in form.inputs)


def fill_form(form: Form, overrides: dict[str, str]) -> dict[str, str]:
    data: dict[str, str] = {}
    for inp in form.inputs:
        if not inp.name or inp.type in ("file", "submit", "button", "image"):
            continue
        if inp.name in overrides:
            data[inp.name] = overrides[inp.name]
        elif inp.type in ("checkbox", "radio"):
            data[inp.name] = inp.value or "1"
        else:
            data[inp.name] = inp.value or "akar"
    for key, value in overrides.items():
        data.setdefault(key, value)
    return data
