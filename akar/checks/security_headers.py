from __future__ import annotations

import re

from ..models import Finding, Page, Severity
from .base import Check

HEADER_SPECS = [
    (
        "strict-transport-security",
        "HSTS",
        Severity.LOW,
        "Serve HTTPS responses with max-age=31536000; includeSubDomains; preload.",
    ),
    (
        "content-security-policy",
        "Content-Security-Policy",
        Severity.LOW,
        "Define a restrictive CSP; avoid unsafe-inline, unsafe-eval and wildcard sources.",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        Severity.LOW,
        "Send X-Content-Type-Options: nosniff.",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        Severity.INFO,
        "Send Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        Severity.INFO,
        "Declare a Permissions-Policy to disable unused browser capabilities.",
    ),
    (
        "cross-origin-opener-policy",
        "Cross-Origin-Opener-Policy",
        Severity.INFO,
        "Send COOP: same-origin to isolate the browsing context.",
    ),
    (
        "cross-origin-resource-policy",
        "Cross-Origin-Resource-Policy",
        Severity.INFO,
        "Send CORP: same-origin on sensitive resources.",
    ),
    (
        "x-permitted-cross-domain-policies",
        "X-Permitted-Cross-Domain-Policies",
        Severity.INFO,
        "Send X-Permitted-Cross-Domain-Policies: none.",
    ),
]


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    return directives


class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "Security headers & CSP"
    description = "Missing/weak HTTP security headers and CSP directives."

    async def on_page(self, ctx, page: Page) -> None:
        if page.url != ctx.base_url:
            return
        self._check_headers(ctx, page)
        self._check_csp(ctx, page)

    def _check_headers(self, ctx, page: Page) -> None:
        is_https = page.url.startswith("https://")
        for header, label, severity, fix in HEADER_SPECS:
            if header == "strict-transport-security" and not is_https:
                continue
            if header not in page.headers:
                ctx.add(
                    Finding(
                        id=f"hdr-missing-{header}",
                        title=f"Missing {label} header",
                        severity=severity,
                        url=page.url,
                        detail=f"The {label} response header is absent on this response.",
                        remediation=fix,
                    )
                )

        hsts = page.headers.get("strict-transport-security", "")
        if not hsts:
            return
        match = re.search(r"max-age=(\d+)", hsts, re.I)
        if match and int(match.group(1)) < 15552000:
            ctx.add(
                Finding(
                    id="hdr-hsts-short",
                    title="HSTS max-age below 180 days",
                    severity=Severity.LOW,
                    url=page.url,
                    detail="Browsers will drop HSTS enforcement sooner, leaving a downgrade window.",
                    evidence=hsts,
                    remediation="Use max-age=31536000; includeSubDomains; preload.",
                )
            )
        if "includeSubDomains" not in hsts:
            ctx.add(
                Finding(
                    id="hdr-hsts-nosub",
                    title="HSTS missing includeSubDomains",
                    severity=Severity.INFO,
                    url=page.url,
                    detail="Subdomains do not inherit HSTS enforcement.",
                    evidence=hsts,
                    remediation="Add includeSubDomains (and preload once stable).",
                )
            )

    def _check_csp(self, ctx, page: Page) -> None:
        csp = page.headers.get("content-security-policy", "")
        report_only = page.headers.get("content-security-policy-report-only", "")

        if not csp:
            if report_only:
                ctx.add(
                    Finding(
                        id="hdr-csp-report-only",
                        title="CSP only in report-only mode",
                        severity=Severity.INFO,
                        url=page.url,
                        detail="A Content-Security-Policy-Report-Only header exists but nothing is enforced.",
                        evidence=report_only[:250],
                        remediation="Promote the policy to an enforcing Content-Security-Policy header.",
                    )
                )
            return

        directives = parse_csp(csp)
        script_src = directives.get("script-src") or directives.get("default-src") or []
        lowered = [token.lower() for token in script_src]

        if "'unsafe-inline'" in lowered:
            ctx.add(
                Finding(
                    id="hdr-csp-unsafe-inline",
                    title="CSP allows 'unsafe-inline' scripts",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    detail="Inline script execution is permitted, weakening XSS defenses.",
                    evidence=csp[:250],
                    remediation="Remove 'unsafe-inline' from script-src; use nonces or hashes.",
                )
            )
        if "'unsafe-eval'" in lowered:
            ctx.add(
                Finding(
                    id="hdr-csp-unsafe-eval",
                    title="CSP allows 'unsafe-eval'",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    detail="eval()/Function() execution is permitted.",
                    evidence=csp[:250],
                    remediation="Remove 'unsafe-eval' from script-src.",
                )
            )
        if "data:" in lowered:
            ctx.add(
                Finding(
                    id="hdr-csp-data-script",
                    title="CSP allows data: URIs in script-src",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    detail="data: URIs can carry executable script.",
                    evidence=csp[:250],
                    remediation="Remove data: from script-src; host scripts yourself.",
                )
            )
        wildcards = [t for t in script_src if t == "*" or (t.startswith("*.") and t.count(".") == 1)]
        if wildcards:
            ctx.add(
                Finding(
                    id="hdr-csp-wildcard",
                    title="CSP script source uses wildcard hosts",
                    severity=Severity.LOW,
                    url=page.url,
                    detail=f"Wildcard tokens: {', '.join(wildcards)}",
                    evidence=csp[:250],
                    remediation="Replace wildcard script hosts with an explicit allowlist.",
                )
            )
        if "default-src" not in directives:
            ctx.add(
                Finding(
                    id="hdr-csp-no-default",
                    title="CSP missing default-src fallback",
                    severity=Severity.LOW,
                    url=page.url,
                    detail="Fetch directives without explicit sources fall back to allowing anything.",
                    evidence=csp[:250],
                    remediation="Add default-src 'self' as a baseline.",
                )
            )
        if "base-uri" not in directives:
            ctx.add(
                Finding(
                    id="hdr-csp-no-base-uri",
                    title="CSP missing base-uri directive",
                    severity=Severity.LOW,
                    url=page.url,
                    detail="An injected <base> tag could redirect relative URLs.",
                    evidence=csp[:250],
                    remediation="Add base-uri 'self'.",
                )
            )
        if "form-action" not in directives:
            ctx.add(
                Finding(
                    id="hdr-csp-no-form-action",
                    title="CSP missing form-action directive",
                    severity=Severity.INFO,
                    url=page.url,
                    detail="Forms may submit to any origin.",
                    evidence=csp[:250],
                    remediation="Add form-action 'self'.",
                )
            )


class ClickjackingCheck(Check):
    id = "clickjacking"
    name = "Clickjacking (XFO / frame-ancestors)"
    description = "Frames the page in a cross-origin iframe."

    async def on_page(self, ctx, page: Page) -> None:
        if page.url != ctx.base_url:
            return
        xfo = page.headers.get("x-frame-options", "")
        csp = page.headers.get("content-security-policy", "")
        frame_match = re.search(r"frame-ancestors([^;]*)", csp, re.I)
        has_frame_ancestors = frame_match is not None

        if not xfo and not has_frame_ancestors:
            ctx.add(
                Finding(
                    id="clickjacking-unframed",
                    title="Page can be framed (no X-Frame-Options / frame-ancestors)",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    detail="Any origin can embed this page in an iframe, enabling clickjacking.",
                    remediation="Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                )
            )
        elif xfo and xfo.strip().lower() not in ("deny", "sameorigin"):
            ctx.add(
                Finding(
                    id="clickjacking-weak-xfo",
                    title="Weak X-Frame-Options value",
                    severity=Severity.LOW,
                    url=page.url,
                    evidence=xfo,
                    remediation="Use X-Frame-Options: DENY or SAMEORIGIN.",
                )
            )

        if frame_match and "*" in frame_match.group(1):
            ctx.add(
                Finding(
                    id="clickjacking-wildcard-fa",
                    title="CSP frame-ancestors allows any origin",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    detail="The frame-ancestors directive contains a wildcard.",
                    evidence=csp[:250],
                    remediation="Restrict frame-ancestors to 'none' or an explicit allowlist.",
                )
            )
