from __future__ import annotations

from ..models import Finding, Severity
from .base import Check

SAFE_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "TRACE"}


class MethodsCheck(Check):
    id = "http-methods"
    name = "HTTP methods & WebDAV"
    description = "OPTIONS/TRACE enumeration, unsafe verbs, WebDAV."

    async def run(self, ctx) -> None:
        base = ctx.base_url
        opts = await ctx.client.options(base, follow=False)
        allow = opts.header("allow")
        acam = opts.header("access-control-allow-methods")
        methods: set[str] = set()
        for src in (allow, acam):
            for token in (src or "").split(","):
                token = token.strip().upper()
                if token:
                    methods.add(token)

        if methods:
            ctx.add(Finding(
                id="methods-advertised",
                title=f"Advertised methods: {', '.join(sorted(methods))}",
                severity=Severity.INFO,
                url=base,
                evidence=f"Allow: {allow or '-'}",
                remediation="Restrict Allow to the verbs the application actually needs.",
            ))

        unsafe = sorted(methods & {"PUT", "DELETE", "PATCH", "MOVE", "COPY", "MKCOL", "PROPFIND", "PROPPATCH", "LOCK"})
        if unsafe:
            ctx.add(Finding(
                id="methods-unsafe",
                title="Unsafe HTTP methods advertised",
                severity=Severity.MEDIUM,
                url=base,
                detail="Write/modify verbs are advertised; unauthenticated clients may attempt them.",
                evidence=", ".join(unsafe),
                remediation="Disable unused methods at the server level and enforce authz on writes.",
            ))

        dav = opts.header("dav")
        if dav:
            ctx.add(Finding(
                id="methods-webdav",
                title="WebDAV enabled",
                severity=Severity.MEDIUM,
                url=base,
                detail="DAV headers indicate WebDAV support, expanding the attack surface (CVE history is deep).",
                evidence=f"DAV: {dav}",
                remediation="Disable WebDAV unless explicitly required.",
            ))

        # direct TRACE probe (cross-site tracing)
        trace = await ctx.client.request("TRACE", base, headers={"X-Akar-Probe": "akar-trace-probe"})
        if trace.status and trace.status < 400 and "akar-trace-probe" in trace.body:
            ctx.add(Finding(
                id="methods-trace-xst",
                title="TRACE echoes request headers (XST risk)",
                severity=Severity.MEDIUM,
                url=base,
                detail="TRACE reflects request headers, historically exploitable for header theft.",
                evidence="Response body contained X-Akar-Probe: akar-trace-probe",
                remediation="Disable TRACE (TraceEnable off / AllowOverride removes it).",
            ))
