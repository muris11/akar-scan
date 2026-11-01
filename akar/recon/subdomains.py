from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import TYPE_CHECKING

from ..models import Finding, Severity

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import Context

log = logging.getLogger("akar.subdomains")

WORDLIST = [
    "www", "mail", "smtp", "pop", "webmail", "mx", "ns1", "ns2", "ftp", "sftp",
    "api", "api2", "app", "apps", "admin", "portal", "dashboard", "panel",
    "dev", "devel", "staging", "stage", "test", "testing", "qa", "uat", "sandbox", "demo", "beta", "alpha",
    "blog", "shop", "store", "shop2", "pay", "checkout", "cart",
    "cdn", "static", "media", "img", "images", "assets", "files", "upload", "uploads", "downloads",
    "vpn", "remote", "gw", "gateway", "edge", "proxy", "jump", "bastion", "rdp",
    "git", "gitlab", "github", "ci", "jenkins", "jira", "confluence", "grafana", "kibana",
    "status", "monitor", "monitoring", "metrics", "health",
    "db", "database", "mysql", "redis", "elastic", "search", "solr",
    "auth", "sso", "login", "oauth", "id", "identity",
    "crm", "erp", "hr", "billing", "invoice",
    "docs", "doc", "support", "help", "helpdesk", "ticket",
    "intranet", "extranet", "internal",
    "m", "mobile", "amp",
    "ws", "wss", "socket", "realtime",
    "cloud", "aws", "azure", "gcp", "k8s", "kube", "docker", "registry",
    "old", "new", "bak", "backup", "legacy", "archive",
    "owa", "exchange", "autodiscover", "cpanel", "webdisk",
    "mail2", "www2", "mx1", "mx2",
    "node1", "node2", "srv1", "srv2",
    "wp", "wordpress", "cms", "forum", "community",
    "ldap", "ad", "dc", "dc1", "ca", "pki",
]


async def _resolve(host: str, timeout: float = 4.0) -> list[str]:
    def _sync() -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
            return sorted({info[4][0] for info in infos})
        except (socket.gaierror, OSError):
            return []

    try:
        return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=timeout)
    except asyncio.TimeoutError:
        return []


async def enumerate(ctx: "Context") -> None:
    from ..utils import domain_of, host_of

    host = host_of(ctx.base_url)
    if not host or host.replace(".", "").isdigit():
        return
    domain = domain_of(host)
    found: set[str] = set()

    if ctx.args.crt:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            page = await ctx.client.get(url, timeout=45.0, retries=1)
            if page.status == 200 and page.body.strip().startswith("["):
                for entry in json.loads(page.body):
                    for name in (entry.get("name_value") or "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain):
                            found.add(name)
        except (json.JSONDecodeError, Exception) as exc:  # noqa: BLE001
            log.debug("crt.sh lookup failed: %s", exc)

    sem = asyncio.Semaphore(40)

    async def probe(word: str) -> None:
        candidate = f"{word}.{domain}"
        async with sem:
            ips = await _resolve(candidate)
        if ips:
            found.add(candidate)
            ctx.subdomains[candidate] = ips

    await asyncio.gather(*(probe(word) for word in WORDLIST))

    sem2 = asyncio.Semaphore(30)

    async def resolve_found(name: str) -> None:
        async with sem2:
            ips = await _resolve(name)
        if ips:
            ctx.subdomains[name] = ips

    remaining = sorted(found - set(ctx.subdomains))
    if remaining:
        await asyncio.gather(*(resolve_found(name) for name in remaining[:400]))

    if ctx.subdomains:
        ctx.add(
            Finding(
                id="recon-subdomains",
                title=f"{len(ctx.subdomains)} live subdomains discovered",
                severity=Severity.INFO,
                url=f"https://{domain}",
                detail="Resolved subdomains found via certificate transparency and DNS brute force.",
                evidence=", ".join(
                    f"{name} ({','.join(ips[:2])})"
                    for name, ips in sorted(ctx.subdomains.items())[:25]
                ),
                remediation="Ensure internal/staging subdomains are not publicly resolvable or reachable.",
            )
        )
