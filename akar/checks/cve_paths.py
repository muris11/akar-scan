from __future__ import annotations

import re

from ..models import Finding, Page, Severity
from ..utils import origin_of
from .base import Check
from .common import looks_like_baseline, spend

WHOOPS_RE = re.compile(r"Whoops!|Symfony\\Component\\Debug|Ignition\\|production\.ERROR|Stack trace", re.I)
DJANGO_DEBUG_RE = re.compile(r"Using the URLconf defined in|Traceback \(most recent call last\)|DisallowedHost|django\.core\.exceptions", re.I)
DEBUG_PIN_RE = re.compile(r"Werkzeug Debugger|Debugger PIN|This is the debugger console", re.I)

PATH_PROBES = [
    # (path, finding id, title, severity, method, confirm-substrings)
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "cve-2017-9841",
     "PHPUnit eval-stdin.php remote code execution (CVE-2017-9841)", Severity.CRITICAL,
     "POST", ["phpinfo()", "PHP Version"]),
    ("/_ignition/health", "ignition-exposed",
     "Laravel Ignition exposed (affected by CVE-2021-3129 on vulnerable versions)", Severity.MEDIUM,
     "GET", ["ignition"]),
    ("/actuator/env", "actuator-env",
     "Spring Boot actuator /env exposed (configuration secrets)", Severity.HIGH,
     "GET", ["propertySources", "activeProfiles"]),
    ("/actuator/heapdump", "actuator-heapdump",
     "Spring Boot heapdump exposed (memory dump, secrets likely)", Severity.HIGH,
     "HEAD", []),
    ("/actuator/mappings", "actuator-mappings",
     "Spring Boot actuator /mappings exposed (route enumeration)", Severity.MEDIUM,
     "GET", ["dispatcherServlet", "handler"]),
    ("/jolokia/list", "jolokia-exposed",
     "Jolokia JMX-over-HTTP exposed (CVE-2018-1000130 risk on old agents)", Severity.MEDIUM,
     "GET", ["type", "mbean"]),
    ("/h2-console", "h2-console",
     "H2 database console exposed", Severity.MEDIUM, "GET", ["h2", "JDBC"]),
    ("/console", "werkzeug-console",
     "Werkzeug/Flask interactive debugger exposed", Severity.HIGH,
     "GET", ["Debugger", "console", "PIN"]),
    ("/solr/", "solr-exposed",
     "Apache Solr admin exposed", Severity.MEDIUM, "GET", ["Solr", "solr"]),
    ("/_cluster/health", "elastic-unauth",
     "Elasticsearch cluster health readable without auth", Severity.HIGH,
     "GET", ["cluster_name", "status"]),
    ("/swagger.json", "swagger-exposed",
     "Swagger/OpenAPI specification exposed (API surface)", Severity.LOW,
     "GET", ["swagger", "paths"]),
    ("/v2/api-docs", "swagger-exposed",
     "Swagger/OpenAPI specification exposed (API surface)", Severity.LOW,
     "GET", ["swagger", "paths"]),
    ("/openapi.json", "swagger-exposed",
     "OpenAPI specification exposed (API surface)", Severity.LOW,
     "GET", ["openapi", "paths"]),
    ("/swagger-ui.html", "swagger-exposed",
     "Swagger UI exposed", Severity.LOW, "GET", ["swagger"]),
    ("/api-docs", "swagger-exposed",
     "API documentation exposed", Severity.LOW, "GET", ["swagger", "paths"]),
    ("/wp-json/wp/v2/users", "wp-user-enum",
     "WordPress user enumeration via REST API", Severity.LOW,
     "GET", ["slug", "name"]),
    ("/xmlrpc.php", "wp-xmlrpc",
     "WordPress XML-RPC enabled (credential brute amplification, pingback SSRF)", Severity.MEDIUM,
     "POST", ["XML-RPC server accepts POST requests", "methodResponse"]),
    ("/wiki/rest/api/content", "confluence-api",
     "Confluence REST API exposed", Severity.INFO, "GET", ["results", "_links"]),
    ("/pages/", "tomcat-manager",
     "Tomcat manager path present", Severity.LOW, "GET", []),
    ("/manager/html", "tomcat-manager",
     "Tomcat manager console present", Severity.LOW, "GET", []),
    ("/host-manager/html", "tomcat-manager",
     "Tomcat host manager present", Severity.LOW, "GET", []),
]

VERSION_CVES = [
    # (regex, component, max version, finding id, title, severity, refs)
    (r"jQuery v(\d+\.\d+(?:\.\d+)?)", "jQuery", "3.5.0", "cve-jquery-xss",
     "jQuery < 3.5.0 (XSS via HTML manipulation, CVE-2020-11022 / CVE-2020-11023)", Severity.MEDIUM),
    (r"jquery[.-]v?(\d+\.\d+(?:\.\d+)?)", "jQuery", "3.5.0", "cve-jquery-xss",
     "jQuery < 3.5.0 (XSS via HTML manipulation, CVE-2020-11022 / CVE-2020-11023)", Severity.MEDIUM),
    (r"angular[.-](\d+\.\d+(?:\.\d+)?)", "AngularJS", "1.8.3", "cve-angularjs-sandbox",
     "AngularJS < 1.8.3 (expression sandbox escape chain)", Severity.LOW),
]


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:4])


def _older(candidate: str, ceiling: str) -> bool:
    try:
        return _version_tuple(candidate) < _version_tuple(ceiling)
    except ValueError:
        return False


class CveCheck(Check):
    id = "cve"
    name = "Known vulnerable paths & components"
    description = "CVE-relevant endpoints and version-based component advisories."

    async def run(self, ctx) -> None:
        origin = origin_of(ctx.base_url)
        ctx.progress("probing known vulnerable paths")

        for path, fid, title, severity, method, confirms in PATH_PROBES:
            if not spend(ctx):
                return
            url = origin + path
            if method == "POST":
                page = await ctx.client.post(url, content=b"<?=phpinfo(); ?>")
            elif method == "HEAD":
                page = await ctx.client.head(url, follow=False)
            else:
                page = await ctx.client.get(url, follow=False)

            if page.error or page.status in (0, 404, 405) or looks_like_baseline(ctx, page):
                continue
            if page.status in (401, 403):
                ctx.add(Finding(id=fid + "-restricted", title=title + " (restricted)",
                                severity=Severity.LOW, url=url,
                                detail="Path exists but requires authentication.",
                                evidence=f"status={page.status}",
                                remediation="Disable unused management endpoints and enforce authn/z."))
                continue
            if page.status >= 500 and not confirms:
                continue
            if confirms:
                body = page.body[:400_000]
                if not any(token.lower() in body.lower() for token in confirms):
                    # HEAD probes (heapdump) accept any non-error status
                    if not (method == "HEAD" and page.status == 200):
                        continue
            if method == "HEAD" and page.status == 200:
                length = page.header("content-length", "?")
                detail = f"Endpoint returns 200 (content-length: {length})."
            else:
                detail = "Endpoint responded with the vulnerable signature."
            ctx.add(Finding(id=fid, title=title, severity=severity, url=url,
                            detail=detail, evidence=f"status={page.status}",
                            remediation="Patch/upgrade the component or remove the exposed endpoint."))

        # framework debug-mode detection on the base page
        base_page = next((p for p in ctx.pages if p.url == ctx.base_url), None)
        if base_page and WHOOPS_RE.search(base_page.body[:200_000]):
            ctx.add(Finding(id="debug-mode-laravel", title="Application debug mode active (stack traces exposed)",
                            severity=Severity.HIGH, url=ctx.base_url,
                            detail="Error pages leak framework internals, paths and environment values.",
                            evidence=_first_line(base_page.body, WHOOPS_RE),
                            remediation="Disable debug mode in production (APP_DEBUG=false)."))
        if base_page and DJANGO_DEBUG_RE.search(base_page.body[:200_000]):
            ctx.add(Finding(id="debug-mode-django", title="Django debug traceback exposed",
                            severity=Severity.HIGH, url=ctx.base_url,
                            detail="DEBUG=True or an unhandled error page leaked an internal traceback.",
                            evidence=_first_line(base_page.body, DJANGO_DEBUG_RE),
                            remediation="Set DEBUG=False and configure a proper error reporter."))
        if base_page and DEBUG_PIN_RE.search(base_page.body[:100_000]):
            ctx.add(Finding(id="debug-console-werkzeug", title="Werkzeug debug console referenced",
                            severity=Severity.HIGH, url=ctx.base_url,
                            evidence=_first_line(base_page.body, DEBUG_PIN_RE),
                            remediation="Disable the interactive debugger in production."))

        self._version_cves(ctx, base_page)

    def _version_cves(self, ctx, page: Page | None) -> None:
        if page is None:
            return
        body = page.body[:400_000]
        for pattern, component, ceiling, fid, title, severity in VERSION_CVES:
            match = re.search(pattern, body, re.I)
            if not match:
                continue
            version = match.group(1)
            if _older(version, ceiling):
                ctx.add(Finding(id=fid, title=title, severity=severity, url=ctx.base_url,
                                param=component, detail=f"Detected {component} {version} (fixed in {ceiling}).",
                                evidence=match.group(0),
                                remediation=f"Upgrade {component} to {ceiling} or later."))


def _first_line(body: str, pattern: re.Pattern) -> str:
    match = pattern.search(body[:200_000])
    if not match:
        return ""
    start = max(0, match.start() - 60)
    return re.sub(r"\s+", " ", body[start : match.end() + 120])[:260]
