from __future__ import annotations

import os
import sys

from ..models import Severity

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
SEVERITY_COLORS = {
    "CRITICAL": "\x1b[1;95m",
    "HIGH": "\x1b[1;91m",
    "MEDIUM": "\x1b[1;93m",
    "LOW": "\x1b[1;96m",
    "INFO": "\x1b[1;90m",
}


def _color_enabled() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


class Painter:
    def __init__(self, enabled: bool | None = None) -> None:
        self.enabled = _color_enabled() if enabled is None else enabled

    def paint(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text

    def severity(self, severity: Severity) -> str:
        label = f"{severity.label:<8}"
        return self.paint(label, SEVERITY_COLORS.get(severity.label, ""))

    @property
    def bold(self) -> str:
        return BOLD if self.enabled else ""

    @property
    def dim(self) -> str:
        return DIM if self.enabled else ""


def render(ctx) -> str:
    p = Painter()
    out: list[str] = []
    counts = ctx.counts()

    out.append("")
    out.append(f"  {p.paint('Akar', BOLD)}  target: {ctx.base_url}")
    stats = ctx.client.stats if ctx.client else {"requests": 0, "errors": 0}
    out.append(
        f"  {p.dim}pages={len(ctx.pages)}  requests={stats.get('requests', 0)}  "
        f"errors={stats.get('errors', 0)}  time={ctx.duration:.1f}s{RESET}"
    )
    out.append("")

    # technology
    if ctx.tech:
        out.append(f"  {p.paint('Technologies', BOLD)}")
        for category in sorted(ctx.tech):
            out.append(f"    {p.dim}{category}:{RESET} {', '.join(ctx.tech[category])}")
        out.append("")

    # recon extras
    if ctx.subdomains:
        out.append(f"  {p.paint(f'Subdomains ({len(ctx.subdomains)})', BOLD)}")
        for name, ips in sorted(ctx.subdomains.items())[:40]:
            out.append(f"    {name}  {p.dim}{', '.join(ips[:3])}{RESET}")
        out.append("")
    if ctx.open_ports:
        out.append(f"  {p.paint(f'Open ports ({len(ctx.open_ports)})', BOLD)}")
        out.append(
            "    "
            + ", ".join(
                f"{port}{f' ({banner[:30]})' if banner else ''}"
                for port, banner in sorted(ctx.open_ports)
            )
        )
        out.append("")

    # findings
    if not ctx.findings:
        out.append(f"  {p.paint('No findings.', BOLD)}")
    else:
        out.append(f"  {p.paint(f'Findings ({len(ctx.findings)})', BOLD)}")
        out.append("")
        current = None
        for finding in ctx.findings:
            if finding.severity != current:
                current = finding.severity
                out.append(f"\n    {p.paint(current.label, SEVERITY_COLORS.get(current.label, ''))}")
            out.append(f"      {p.severity(finding.severity)}  {p.paint(finding.title, BOLD)}")
            if finding.param:
                out.append(f"                param: {finding.param}")
            out.append(f"                url:   {finding.url}")
            if finding.detail:
                out.append(f"                info:  {finding.detail}")
            if finding.evidence:
                out.append(f"                evid:  {_clip(finding.evidence, 300)}")
            if finding.remediation:
                out.append(f"                fix:   {finding.remediation}")
            out.append("")

    # summary bar
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    summary = " | ".join(
        f"{p.severity(sev).strip()} {counts[sev.label]}" for sev in order
    )
    out.append(f"  {p.paint('Summary', BOLD)}  {summary}")
    out.append("")
    return "\n".join(out)


def _clip(text: str, size: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= size else text[: size - 3] + "..."
