from __future__ import annotations

import asyncio
import re

from ..models import Finding, Severity
from ..utils import origin_of
from .base import Check
from .common import looks_like_baseline, spend

AUTO_ARCHIVE = "AUTO_ARCHIVE"
# Marker: match a dotenv-style file structurally (KEY=value lines) instead of a
# fixed keyword whitelist, so any real .env is caught regardless of key names.
ENV_LIKE = "ENV_LIKE"

# A single dotenv assignment line, e.g. "DB_PASS=rahasia", "export API_KEY='x'".
_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]{0,64})\s*=", re.M)
# Keys that make even a lone assignment line worth flagging as a secret file.
_SECRET_KEY_RE = re.compile(
    r"(pass|secret|token|key|cred|dsn|salt|sign|auth|database|db_|url|host|user)",
    re.I,
)
_MIN_ENV_LINES = 2


class Target:
    __slots__ = ("path", "fid", "title", "severity", "signatures", "note")

    def __init__(self, path, fid, title, severity, signatures=None, note=""):
        self.path = path
        self.fid = fid
        self.title = title
        self.severity = severity
        self.signatures = signatures or []
        self.note = note


# (path, finding id, title, severity, content signatures)
TARGETS = [
    # VCS metadata
    ("/.git/HEAD", "exposed-git", "Git metadata exposed (.git/HEAD)", Severity.HIGH, ["ref: refs/heads/"]),
    ("/.git/config", "exposed-git-config", "Git config exposed (repository URL / user.email)", Severity.HIGH, ["[core]", "[remote"]),
    ("/.svn/entries", "exposed-svn", "Subversion metadata exposed", Severity.HIGH, []),
    ("/.svn/wc.db", "exposed-svn-db", "Subversion working copy database exposed", Severity.HIGH, ["SQLite format 3"]),
    ("/.hg/hgrc", "exposed-hg", "Mercurial config exposed", Severity.HIGH, ["[paths]"]),

    # Secrets & credentials
    # ENV_LIKE: any dotenv-style KEY=value file counts (real .env files use
    # arbitrary key names, so a keyword whitelist would miss them).
    ("/.env", "exposed-env", ".env file exposed (application secrets)", Severity.CRITICAL, [ENV_LIKE]),
    ("/.env.local", "exposed-env", ".env.local exposed (application secrets)", Severity.CRITICAL, [ENV_LIKE]),
    ("/.env.backup", "exposed-env", ".env backup exposed", Severity.CRITICAL, [ENV_LIKE]),
    ("/.env.production", "exposed-env", ".env.production exposed", Severity.CRITICAL, [ENV_LIKE]),
    ("/.env.bak", "exposed-env", ".env backup exposed", Severity.CRITICAL, [ENV_LIKE]),
    ("/wp-config.php.bak", "exposed-wpconfig", "wp-config.php backup exposed (DB credentials)", Severity.CRITICAL,
     ["DB_PASSWORD", "DB_USER", "table_prefix"]),
    ("/wp-config.php~", "exposed-wpconfig", "wp-config.php backup exposed (DB credentials)", Severity.CRITICAL,
     ["DB_PASSWORD", "DB_USER"]),
    ("/wp-config.php.save", "exposed-wpconfig", "wp-config.php backup exposed (DB credentials)", Severity.CRITICAL,
     ["DB_PASSWORD", "DB_USER"]),
    ("/wp-config.php.old", "exposed-wpconfig", "wp-config.php backup exposed (DB credentials)", Severity.CRITICAL,
     ["DB_PASSWORD", "DB_USER"]),
    ("/.ssh/id_rsa", "exposed-ssh-key", "SSH private key exposed", Severity.CRITICAL,
     ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN DSA PRIVATE KEY"]),
    ("/id_rsa", "exposed-ssh-key", "SSH private key exposed", Severity.CRITICAL,
     ["BEGIN OPENSSH PRIVATE KEY", "BEGIN RSA PRIVATE KEY"]),
    ("/.aws/credentials", "exposed-aws", "AWS credentials file exposed", Severity.CRITICAL,
     ["aws_access_key_id", "[default]"]),
    ("/.git-credentials", "exposed-gitcred", "Git credentials file exposed", Severity.HIGH, ["https://", "@"]),
    ("/.netrc", "exposed-netrc", ".netrc credentials file exposed", Severity.HIGH, ["machine ", "login "]),
    ("/.npmrc", "exposed-npmrc", ".npmrc exposed (registry token)", Severity.HIGH, ["_authToken", "//"]),
    ("/.htpasswd", "exposed-htpasswd", "Password file (.htpasswd) exposed", Severity.HIGH, [":"]),
    ("/.bash_history", "exposed-history", "Shell history exposed", Severity.HIGH, ["sudo ", "export ", "curl ", "git ", "ssh "]),
    ("/.zsh_history", "exposed-history", "Shell history exposed", Severity.HIGH, [":", ";"]),

    # Backups / data
    ("/dump.sql", "exposed-db", "Database dump exposed", Severity.CRITICAL, ["INSERT INTO", "CREATE TABLE"]),
    ("/database.sql", "exposed-db", "Database dump exposed", Severity.CRITICAL, ["INSERT INTO", "CREATE TABLE"]),
    ("/backup.sql", "exposed-db", "Database dump exposed", Severity.CRITICAL, ["INSERT INTO", "CREATE TABLE"]),
    ("/db.sql", "exposed-db", "Database dump exposed", Severity.CRITICAL, ["INSERT INTO", "CREATE TABLE"]),
    ("/site.zip", "exposed-archive", "Site source archive exposed", Severity.HIGH, [AUTO_ARCHIVE]),
    ("/www.zip", "exposed-archive", "Site source archive exposed", Severity.HIGH, [AUTO_ARCHIVE]),
    ("/backup.zip", "exposed-archive", "Backup archive exposed", Severity.HIGH, [AUTO_ARCHIVE]),
    ("/backup.tar.gz", "exposed-archive", "Backup archive exposed", Severity.HIGH, [AUTO_ARCHIVE]),
    ("/backup.bak", "exposed-backup", "Backup file exposed", Severity.HIGH, []),

    # Debug / info endpoints
    ("/phpinfo.php", "exposed-phpinfo", "phpinfo() exposed", Severity.HIGH, ["phpinfo()", "PHP Version"]),
    ("/info.php", "exposed-phpinfo", "phpinfo() exposed", Severity.HIGH, ["phpinfo()", "PHP Version"]),
    ("/test.php", "exposed-phpinfo", "phpinfo() exposed", Severity.HIGH, ["phpinfo()", "PHP Version"]),
    ("/server-status", "exposed-apache-status", "Apache server-status exposed", Severity.MEDIUM,
     ["Apache Server Status", "Server Version:"]),
    ("/server-info", "exposed-apache-info", "Apache server-info exposed", Severity.MEDIUM,
     ["Server Information", "Server Version:"]),
    ("/elmah.axd", "exposed-elmah", "ELMAH error log exposed", Severity.HIGH, ["Error Log", "ELMAH"]),
    ("/trace.axd", "exposed-trace", "ASP.NET trace exposed", Severity.HIGH, ["Request Details", "Trace Information"]),
    ("/actuator/env", "exposed-actuator-env", "Spring Boot actuator env exposed (config secrets)", Severity.HIGH,
     ["propertySources", "activeProfiles"]),
    ("/actuator/configprops", "exposed-actuator-config", "Spring Boot configprops exposed", Severity.HIGH,
     ["propertySources", "contexts"]),
    ("/actuator/health", "exposed-actuator", "Spring Boot actuator exposed", Severity.LOW, ['"status"']),
    ("/console", "exposed-console", "Framework debug console exposed", Severity.HIGH, ["Debugger", "console", "PIN"]),
    ("/_profiler", "exposed-profiler", "Symfony profiler exposed", Severity.MEDIUM, ["Profiler", "profiler"]),
    ("/__debug__/", "exposed-debugtoolbar", "Debug toolbar exposed", Severity.MEDIUM, ["Django Debug Toolbar", "djdt"]),

    # Config / source
    ("/web.config", "exposed-webconfig", "IIS web.config exposed", Severity.HIGH, ["<configuration", "<system.web"]),
    ("/appsettings.json", "exposed-appsettings", "ASP.NET appsettings exposed", Severity.HIGH,
     ["ConnectionStrings", "\"Logging\""]),
    ("/config.json", "exposed-config", "Config file exposed", Severity.MEDIUM, ["\"apiKey\"", "\"secret\"", "\"password\"", "\"db\""]),
    ("/settings.py", "exposed-django-settings", "Django settings module exposed", Severity.HIGH,
     ["SECRET_KEY", "DATABASES", "ALLOWED_HOSTS"]),
    ("/database.yml", "exposed-db-config", "Database config exposed", Severity.HIGH,
     ["password:", "database:", "adapter:"]),
    ("/application.properties", "exposed-properties", "Application properties exposed", Severity.HIGH,
     ["spring.", "password", "datasource"]),
    ("/.htaccess", "exposed-htaccess", ".htaccess exposed", Severity.LOW, ["RewriteEngine", "php_value", "Deny from"]),
    ("/config.php.bak", "exposed-config-backup", "PHP config backup exposed", Severity.HIGH,
     ["password", "$db", "mysql_connect", "PDO"]),
    ("/.idea/workspace.xml", "exposed-idea", "IDE workspace file exposed (paths, configs)", Severity.LOW,
     ["<project", "project-version"]),
    ("/sftp-config.json", "exposed-sftp-config", "SFTP config exposed (host/credentials)", Severity.HIGH,
     ["\"host\"", "\"user\""]),
    ("/.vscode/sftp.json", "exposed-sftp-config", "SFTP config exposed (host/credentials)", Severity.HIGH,
     ["\"host\"", "\"user\""]),
    ("/.DS_Store", "exposed-dsstore", "Directory metadata (.DS_Store) exposed", Severity.LOW,
     ["Bud1", "DSDB"]),

    # CI / infra
    ("/.gitlab-ci.yml", "exposed-ci", "CI pipeline config exposed", Severity.LOW, [":", "- "]),
    ("/Jenkinsfile", "exposed-ci", "Jenkins pipeline exposed", Severity.LOW, ["pipeline", "stage("]),
    ("/Dockerfile", "exposed-dockerfile", "Dockerfile exposed", Severity.INFO, ["FROM ", "RUN ", "COPY "]),
    ("/docker-compose.yml", "exposed-compose", "docker-compose config exposed", Severity.LOW,
     ["services:", "image:", "environment:"]),
    ("/.travis.yml", "exposed-ci", "Travis CI config exposed", Severity.INFO, ["language:", "script:"]),

    # Logs
    ("/storage/logs/laravel.log", "exposed-log", "Application log exposed", Severity.MEDIUM,
     ["production.ERROR", "local.INFO", "stack trace"]),
    ("/error_log", "exposed-log", "error_log exposed", Severity.MEDIUM, ["PHP", "Fatal error", "error"]),
    ("/logs/error.log", "exposed-log", "Error log exposed", Severity.MEDIUM, ["error", "warn"]),

    # Misc
    ("/crossdomain.xml", "exposed-crossdomain", "crossdomain.xml present", Severity.INFO,
     ["<cross-domain-policy"]),
    ("/.well-known/security.txt", "security-txt", "security.txt published", Severity.INFO, ["Contact:"]),
    ("/phpunit.xml", "exposed-phpunit", "phpunit config exposed", Severity.LOW, ["<phpunit", "testsuite"]),
    ("/composer.json", "exposed-composer", "composer.json exposed", Severity.INFO, ["require", "\"name\""]),
    ("/.dockerignore", "exposed-dockerignore", ".dockerignore exposed", Severity.INFO, []),
]


class ExposedFilesCheck(Check):
    id = "exposed-files"
    name = "Exposed sensitive files"
    description = "Secrets, VCS metadata, backups, configs, and debug endpoints."

    async def run(self, ctx) -> None:
        origin = origin_of(ctx.base_url)
        ctx.progress(f"probing {len(TARGETS)} sensitive paths")
        sem = asyncio.Semaphore(max(2, min(ctx.args.threads, 16)))

        async def probe(spec):
            async with sem:
                if not spend(ctx):
                    return None
                target = Target(*spec)
                page = await ctx.client.get(origin + target.path, follow=False)
                return target, page

        results = await asyncio.gather(*(probe(t) for t in TARGETS))
        for result in results:
            if result is None:
                continue
            target, page = result
            self._evaluate(ctx, origin, target, page)

    def _evaluate(self, ctx, origin: str, target: Target, page) -> None:
        if page.error:
            return
        url = origin + target.path

        if page.status in (401, 403):
            ctx.add(
                Finding(
                    id=target.fid + "-restricted",
                    title=f"{target.title} (access restricted but path exists)",
                    severity=Severity.LOW,
                    url=url,
                    detail="The server answers 401/403 for this path, confirming it exists.",
                    evidence=f"status={page.status}",
                    remediation="Remove the resource; do not rely on access control alone.",
                )
            )
            return

        if page.status != 200 or looks_like_baseline(ctx, page):
            return

        signatures = target.signatures

        if ENV_LIKE in signatures:
            self._evaluate_env_like(ctx, url, target, page)
            return

        if AUTO_ARCHIVE in signatures:
            ct = (page.content_type or "").lower()
            length = int(page.header("content-length", "0") or "0")
            if "html" in ct and length < 1000 and not page.body.startswith("PK"):
                return
            ctx.add(Finding(id=target.fid, title=target.title, severity=target.severity, url=url,
                            detail=f"Archive/config served with content-type {ct or 'unknown'}.",
                            evidence=f"status=200, content-length={length or len(page.body)}",
                            remediation="Remove backups from the web root; serve them from private storage."))
            return

        if signatures:
            body = page.body[:400_000]
            if not any(sig in body for sig in signatures):
                return
            ctx.add(
                Finding(
                    id=target.fid,
                    title=target.title,
                    severity=target.severity,
                    url=url,
                    detail=target.note or "File content matches the expected sensitive pattern.",
                    evidence=f"signature matched; status=200; length={len(page.body)}",
                    remediation="Delete the file from the web root and rotate any exposed secrets.",
                )
            )
            return

        # no signature: accept a non-fallback 200
        if page.is_html and ctx.baseline and page.title and page.title == ctx.baseline.title:
            return
        ctx.add(
            Finding(
                id=target.fid,
                title=target.title,
                severity=Severity.INFO if page.is_html else target.severity,
                url=url,
                detail="Path returned 200 for a non-fallback response.",
                evidence=f"status=200, content-type={page.content_type or '-'}, length={len(page.body)}",
                remediation="Remove the file from the web root.",
            )
        )

    def _evaluate_env_like(self, ctx, url: str, target: Target, page) -> None:
        """Detect a dotenv-style secrets file by structure, not by keyword.

        A real .env uses arbitrary key names (DB_PASS, REDIS_URL, STRIPE_KEY...),
        so matching a fixed keyword whitelist causes false negatives. Instead we
        count assignment-looking lines and require either several of them or a
        single secret-looking key — while rejecting HTML fallback pages.
        """
        if page.is_html:
            # An HTML response is the site's fallback page, not an env file.
            return
        body = page.body[:400_000]
        if not body.strip():
            return

        keys = _ENV_LINE_RE.findall(body)
        if not keys:
            return
        secret_keys = [k for k in keys if _SECRET_KEY_RE.search(k)]
        if len(keys) < _MIN_ENV_LINES and not secret_keys:
            return

        shown = ", ".join(keys[:6]) + (", …" if len(keys) > 6 else "")
        ctx.add(
            Finding(
                id=target.fid,
                title=target.title,
                severity=target.severity,
                url=url,
                detail=(
                    "The server returns a dotenv-style file with plaintext "
                    f"assignments ({len(keys)} variable(s): {shown})."
                ),
                evidence=f"status=200; content-type={page.content_type or '-'}; length={len(page.body)}",
                remediation="Delete the file from the web root and rotate every exposed secret.",
            )
        )
