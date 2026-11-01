from __future__ import annotations

from .base import Check
from .cookies import CookiesCheck
from .cors import CorsCheck
from .cve_paths import CveCheck
from .csrf import CsrfCheck
from .exposed import ExposedFilesCheck
from .http_policy import HttpPolicyCheck
from .info_leak import InfoLeakCheck
from .lfi import LfiCheck
from .methods import MethodsCheck
from .open_redirect import OpenRedirectCheck
from .security_headers import ClickjackingCheck, SecurityHeadersCheck
from .sqli import SqliCheck
from .ssl_tls import TlsCheck
from .xss import XssCheck

ALL_CHECKS: list[Check] = [
    SecurityHeadersCheck(),
    ClickjackingCheck(),
    CookiesCheck(),
    CorsCheck(),
    TlsCheck(),
    ExposedFilesCheck(),
    CveCheck(),
    OpenRedirectCheck(),
    XssCheck(),
    SqliCheck(),
    LfiCheck(),
    CsrfCheck(),
    InfoLeakCheck(),
    MethodsCheck(),
    HttpPolicyCheck(),
]

RECON_MODULES = [
    ("subdomains", "Certificate transparency + DNS brute-force subdomain discovery (enable with --subdomains)"),
    ("ports", "Async TCP port scan of the target host (enable with --ports)"),
]


def build_checks(only=None, skip=None) -> list[Check]:
    only_set = {x.strip().lower() for x in (only or []) if x.strip()}
    skip_set = {x.strip().lower() for x in (skip or []) if x.strip()}
    selected: list[Check] = []
    for check in ALL_CHECKS:
        if only_set and check.id not in only_set:
            continue
        if check.id in skip_set:
            continue
        selected.append(check)
    return selected
