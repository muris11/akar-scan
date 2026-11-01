from __future__ import annotations

import re
import secrets
from difflib import SequenceMatcher
from urllib.parse import (
    parse_qsl,
    quote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

DEFAULT_PORTS = {"http": 80, "https": 443}

ASSET_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|bmp|css|woff2?|ttf|otf|eot|mp[34]|wav|ogg|"
    r"avi|mov|mkv|flv|pdf|zip|rar|7z|gz|tgz|exe|dmg|iso|bin|docx?|xlsx?|pptx?|"
    r"torrent|wasm)$",
    re.I,
)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    netloc = host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def canonical_url(url: str) -> str:
    p = urlsplit(normalize_url(url))
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
    path = p.path or "/"
    base = f"{p.scheme}://{p.netloc}{path}"
    return f"{base}?{query}" if query else base


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def origin_of(url: str) -> str:
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    port = p.port
    netloc = host if (not port or port == DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def domain_of(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_same_site(base_url: str, other_url: str, include_subdomains: bool = False) -> bool:
    b = host_of(base_url)
    o = host_of(other_url)
    if not b or not o:
        return False
    if b == o:
        return True
    if include_subdomains:
        return domain_of(o) == domain_of(b) and bool(domain_of(b))
    return False


def build_url(url: str, param: str, value: str) -> str:
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    replaced = False
    for k, v in pairs:
        if k == param and not replaced:
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((param, value))
    query = urlencode(out, doseq=True, quote_via=quote)
    return urlunsplit((p.scheme, p.netloc, p.path, query, ""))


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in (spec or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if hi < lo:
                lo, hi = hi, lo
            ports.update(range(max(1, lo), min(65535, hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)[:3000]


def rand_token(n: int = 6) -> str:
    return secrets.token_hex((n + 1) // 2)[:n]


def clip(s: str, n: int = 280) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html)


def similarity(a: str, b: str) -> float:
    sa = strip_tags(a).lower()[:30000]
    sb = strip_tags(b).lower()[:30000]
    if not sa or not sb:
        return 0.0
    return SequenceMatcher(None, sa, sb).ratio()


def is_asset(url: str) -> bool:
    return bool(ASSET_RE.search(urlsplit(url).path))


def parse_cookie_header(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_set_cookie(raw: str) -> tuple[str, str, dict[str, str]]:
    """Return (name, value, attrs) from a raw Set-Cookie header line."""
    segments = raw.split(";")
    name, value = "", ""
    if segments and "=" in segments[0]:
        name, value = segments[0].split("=", 1)
        name, value = name.strip(), value.strip()
    attrs: dict[str, str] = {}
    for seg in segments[1:]:
        seg = seg.strip()
        if not seg:
            continue
        if "=" in seg:
            k, v = seg.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[seg.lower()] = ""
    return name, value, attrs


def snippet_around(text: str, needle: str, before: int = 70, after: int = 90) -> str:
    idx = text.find(needle)
    if idx < 0:
        return clip(text[: before + after])
    start = max(0, idx - before)
    return clip(text[start : idx + len(needle) + after])


def urljoin_safe(base: str, link: str) -> str:
    return urljoin(base, link.strip())
