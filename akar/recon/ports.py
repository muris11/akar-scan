from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ..models import Finding, Severity
from ..utils import host_of, parse_ports

if TYPE_CHECKING:  # pragma: no cover
    from ..engine import Context

log = logging.getLogger("akar.ports")

COMMON = "80,443,8080,8443,8000,8888,3000,5000,9090,2082,2083,2086,2087,2096,10000,81,4443,9443,6443"
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 993, 995, 3306, 5432, 6379, 27017, 11211}


async def scan(ctx: "Context") -> None:
    host = host_of(ctx.base_url)
    if not host:
        return
    spec = ctx.args.ports
    if spec is True or spec == "":
        spec = COMMON
    ports = parse_ports(str(spec))
    if not ports:
        return
    ctx.progress(f"scanning {len(ports)} ports on {host}")
    sem = asyncio.Semaphore(max(1, ctx.args.threads))

    async def probe(port: int):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=ctx.args.port_timeout
                )
            except (OSError, asyncio.TimeoutError):
                return None
            banner = b""
            if port in BANNER_PORTS:
                try:
                    banner = await asyncio.wait_for(reader.read(256), timeout=1.2)
                except (OSError, asyncio.TimeoutError):
                    banner = b""
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass
            return port, banner.decode(errors="replace").strip()

    results = await asyncio.gather(*(probe(p) for p in ports))
    for item in results:
        if item:
            ctx.open_ports.append(item)

    if ctx.open_ports:
        evidence = ", ".join(
            f"{port}{f' [{banner[:40]}]' if banner else ''}"
            for port, banner in sorted(ctx.open_ports)
        )
        ctx.add(
            Finding(
                id="recon-open-ports",
                title=f"{len(ctx.open_ports)} open ports on {host}",
                severity=Severity.INFO,
                url=ctx.base_url,
                detail="TCP ports accepting connections during this scan.",
                evidence=evidence,
                remediation="Restrict exposed services to required ports and firewall the rest.",
            )
        )
