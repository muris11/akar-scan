from __future__ import annotations

import asyncio
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone

from ..models import Finding, Severity
from ..utils import host_of
from .base import Check

WEAK_CIPHERS = [
    ("3DES", "DES-CBC3-SHA"),
    ("RC4", "RC4-SHA"),
    ("RC4-MD5", "RC4-MD5"),
    ("NULL", "NULL"),
    ("EXPORT", "EXP-RC4-MD5"),
    ("anon-ADH", "ADH"),
]


async def _grab_cert(host: str, port: int):
    def _sync():
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            os.write(fd, pem.encode())
            os.close(fd)
            info = ssl._ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib-only cert parse
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        return info

    return await asyncio.to_thread(_sync)


async def _proto_supported(host: str, port: int, version) -> bool | None:
    def _sync() -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True

    try:
        return await asyncio.to_thread(_sync)
    except ssl.SSLError:
        return False
    except OSError:
        return None


async def _weak_cipher_supported(host: str, port: int, cipher: str) -> bool | None:
    def _sync() -> bool:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            return False
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError:
            return False
        with socket.create_connection((host, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True

    try:
        return await asyncio.to_thread(_sync)
    except ssl.SSLError:
        return False
    except OSError:
        return None


class TlsCheck(Check):
    id = "tls"
    name = "TLS/SSL configuration"
    description = "Certificate validity, protocol support, and weak ciphers."

    async def run(self, ctx) -> None:
        if not ctx.base_url.startswith("https://"):
            return
        host = host_of(ctx.base_url)
        port = int(ctx.base_url.split("//", 1)[1].split("/", 1)[0].split(":")[1]) if ":" in ctx.base_url.split("//", 1)[1].split("/", 1)[0] else 443
        if not host:
            return
        ctx.progress(f"TLS analysis on {host}:{port}")

        try:
            cert = await _grab_cert(host, port)
        except Exception as exc:  # noqa: BLE001
            ctx.add(
                Finding(
                    id="tls-unreachable",
                    title="TLS handshake could not be completed",
                    severity=Severity.INFO,
                    url=ctx.base_url,
                    detail=f"Certificate analysis failed: {type(exc).__name__}: {exc}",
                    remediation="Verify the TLS endpoint is reachable on the scanned port.",
                )
            )
            return

        ctx.tls = cert or {}

        # expiry
        try:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            days_left = int((not_after - datetime.now(timezone.utc).timestamp()) / 86400)
            when = datetime.fromtimestamp(not_after, tz=timezone.utc).strftime("%Y-%m-%d")
            if days_left < 0:
                severity, title = Severity.HIGH, "TLS certificate expired"
            elif days_left < 14:
                severity, title = Severity.HIGH, "TLS certificate expires within 14 days"
            elif days_left < 30:
                severity, title = Severity.MEDIUM, "TLS certificate expires within 30 days"
            elif days_left < 90:
                severity, title = Severity.LOW, "TLS certificate expires within 90 days"
            else:
                severity = None
            if severity is not None:
                ctx.add(
                    Finding(
                        id="tls-expiry",
                        title=title,
                        severity=severity,
                        url=ctx.base_url,
                        detail=f"notAfter: {when} ({days_left} days left).",
                        evidence=f"issuer={dict(cert.get('issuer', ())).get('commonName', '?')}",
                        remediation="Automate certificate renewal with ACME/Let's Encrypt or your CA.",
                    )
                )
        except Exception:  # noqa: BLE001
            pass

        # self-signed
        issuer = dict(cert.get("issuer", ())).get("commonName", "")
        subject = dict(cert.get("subject", ())).get("commonName", "")
        if issuer and subject and issuer == subject:
            ctx.add(
                Finding(
                    id="tls-self-signed",
                    title="Certificate is self-signed",
                    severity=Severity.MEDIUM,
                    url=ctx.base_url,
                    detail=f"Subject CN equals issuer CN: {subject}.",
                    remediation="Use a certificate issued by a trusted CA.",
                )
            )

        # hostname mismatch
        sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
        if sans and not _host_matches(host, sans):
            ctx.add(
                Finding(
                    id="tls-hostname-mismatch",
                    title="Certificate SAN does not cover the scanned host",
                    severity=Severity.MEDIUM,
                    url=ctx.base_url,
                    detail=f"Host: {host}; SANs: {', '.join(sans[:8])}",
                    remediation="Issue a certificate that covers this hostname.",
                )
            )

        # protocol support
        proto_checks = [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ]
        supported: list[str] = []
        for label, version in proto_checks:
            ok = await _proto_supported(host, port, version)
            if ok:
                supported.append(label)
        ctx.tls["protocols"] = supported

        for legacy in ("TLS 1.0", "TLS 1.1"):
            if legacy in supported:
                ctx.add(
                    Finding(
                        id=f"tls-legacy-{legacy.replace(' ', '').lower()}",
                        title=f"{legacy} is supported",
                        severity=Severity.MEDIUM,
                        url=ctx.base_url,
                        detail=f"The server negotiates {legacy}, which has known weaknesses (BEAST, POODLE-class issues).",
                        evidence=f"Accepted protocols: {', '.join(supported)}",
                        remediation=f"Disable {legacy}; require TLS 1.2+.",
                    )
                )

        # weak ciphers (only worth probing if TLS 1.2 or below is available)
        if any(p in supported for p in ("TLS 1.0", "TLS 1.1", "TLS 1.2")):
            for label, cipher in WEAK_CIPHERS:
                ok = await _weak_cipher_supported(host, port, cipher)
                if ok:
                    ctx.add(
                        Finding(
                            id=f"tls-weak-cipher-{label.lower()}",
                            title=f"Weak cipher suite accepted ({label})",
                            severity=Severity.MEDIUM,
                            url=ctx.base_url,
                            detail=f"The server offers cipher suites in the {label} class.",
                            evidence=f"probe cipher: {cipher}",
                            remediation="Remove weak cipher suites from the server configuration.",
                        )
                    )


def _host_matches(host: str, sans: list[str]) -> bool:
    host = host.lower()
    for san in sans:
        san = san.lower()
        if san.startswith("*."):
            suffix = san[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
        elif san == host:
            return True
    return False
