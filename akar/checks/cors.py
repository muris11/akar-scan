from __future__ import annotations

from ..models import Finding, Severity
from .base import Check

EVIL_ORIGIN = "https://akarcors.invalid"


class CorsCheck(Check):
    id = "cors"
    name = "CORS misconfiguration"
    description = "Origin reflection, wildcard, and permissive preflight."

    async def run(self, ctx) -> None:
        targets = [ctx.base_url]
        for page in ctx.pages:
            if ("api" in page.url or "?" in page.url) and page.url not in targets:
                targets.append(page.url)
            if len(targets) >= 5:
                break

        for url in targets:
            resp = await ctx.client.get(url, headers={"Origin": EVIL_ORIGIN}, follow=False)
            acao = resp.header("access-control-allow-origin")
            acac = resp.header("access-control-allow-credentials").lower()
            if not acao:
                continue

            if acao == EVIL_ORIGIN:
                severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
                ctx.add(
                    Finding(
                        id="cors-reflected-origin",
                        title="CORS reflects arbitrary Origin",
                        severity=severity,
                        url=url,
                        detail=(
                            "Access-Control-Allow-Origin echoes the attacker-controlled Origin"
                            + (" with credentials allowed." if acac == "true" else ".")
                        ),
                        evidence=f"Origin: {EVIL_ORIGIN} -> ACAO: {acao}; ACAC: {acac or '-'}",
                        remediation="Return ACAO only for an explicit allowlist of trusted origins.",
                    )
                )
                return

            if acao == "*" and acac == "true":
                ctx.add(
                    Finding(
                        id="cors-wildcard-credentials",
                        title="CORS wildcard combined with Allow-Credentials",
                        severity=Severity.MEDIUM,
                        url=url,
                        detail="Browsers reject this combination; signals a broken CORS policy.",
                        evidence=f"ACAO: *; ACAC: {acac}",
                        remediation="Replace * with an explicit origin allowlist.",
                    )
                )
                return

            if acao == "*":
                ctx.add(
                    Finding(
                        id="cors-wildcard",
                        title="CORS allows any origin (wildcard)",
                        severity=Severity.LOW,
                        url=url,
                        detail="Any site may read responses from this endpoint.",
                        evidence="Access-Control-Allow-Origin: *",
                        remediation="Limit CORS to the origins that require access.",
                    )
                )
                return

        # preflight probe for overly broad verbs
        target = targets[0]
        pre = await ctx.client.request(
            "OPTIONS",
            target,
            headers={"Origin": EVIL_ORIGIN, "Access-Control-Request-Method": "DELETE"},
            follow=False,
        )
        pre_acao = pre.header("access-control-allow-origin")
        pre_methods = pre.header("access-control-allow-methods", "")
        if pre_acao == EVIL_ORIGIN and "DELETE" in pre_methods.upper():
            ctx.add(
                Finding(
                    id="cors-preflight-delete",
                    title="Preflight permits cross-origin DELETE",
                    severity=Severity.MEDIUM,
                    url=target,
                    detail="The endpoint advertises cross-origin DELETE to any origin.",
                    evidence=f"Access-Control-Allow-Methods: {pre_methods}",
                    remediation="Restrict allowed methods and origins to actual requirements.",
                )
            )
