from __future__ import annotations

import html as _html

from ..models import Severity

SEVERITY_COLORS = {
    "CRITICAL": "#ff4d94",
    "HIGH": "#ff5f56",
    "MEDIUM": "#ffb020",
    "LOW": "#4fc3f7",
    "INFO": "#9aa4b2",
}

CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; background:#0d1117; color:#e6edf3;
  font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
.wrap { max-width:1080px; margin:0 auto; padding:32px 20px 80px; }
header h1 { margin:0 0 4px; font-size:24px; letter-spacing:-.01em; }
header .meta { color:#9aa4b2; font-size:13px; word-break:break-all; }
.stats { display:flex; flex-wrap:wrap; gap:10px; margin:20px 0 6px; }
.stat { background:#161b22; border:1px solid #21262d; border-radius:8px; padding:10px 14px; min-width:96px; }
.stat b { display:block; font-size:20px; line-height:1.2; }
.stat span { color:#9aa4b2; font-size:11px; text-transform:uppercase; letter-spacing:.06em; }
.filters { display:flex; gap:8px; margin:22px 0 14px; flex-wrap:wrap; }
.filters button { background:#161b22; color:#e6edf3; border:1px solid #30363d;
  border-radius:99px; padding:5px 14px; font-size:12px; cursor:pointer; }
.filters button:hover { border-color:#8b949e; }
.filters button.active { background:#e6edf3; color:#0d1117; }
.tech { margin:14px 0 4px; color:#9aa4b2; font-size:13px; }
.tech b { color:#e6edf3; }
article { background:#161b22; border:1px solid #21262d; border-left-width:4px;
  border-radius:8px; padding:14px 16px; margin:10px 0; }
article .sev { display:inline-block; font-size:11px; font-weight:700; letter-spacing:.08em;
  padding:2px 8px; border-radius:4px; margin-right:8px; color:#0d1117; }
article h3 { display:inline; font-size:15px; margin:0; }
article dl { display:grid; grid-template-columns:76px 1fr; gap:2px 12px; margin:10px 0 0; font-size:13px; }
article dt { color:#9aa4b2; }
article dd { margin:0; word-break:break-word; }
article pre { background:#0d1117; border:1px solid #21262d; border-radius:6px;
  padding:8px 10px; margin:8px 0 0; font-size:12px; white-space:pre-wrap; word-break:break-all; }
.empty { color:#9aa4b2; padding:24px 0; }
footer { margin-top:34px; color:#484f58; font-size:12px; }
"""


def _esc(value: str) -> str:
    return _html.escape(str(value or ""), quote=True)


def render(ctx) -> str:
    stats = ctx.client.stats if ctx.client else {}
    counts = ctx.counts()

    cards: list[str] = []
    for finding in ctx.findings:
        sev = finding.severity.label
        color = SEVERITY_COLORS.get(sev, "#9aa4b2")
        rows = []
        if finding.url:
            rows.append(f"<dt>URL</dt><dd>{_esc(finding.url)}</dd>")
        if finding.param:
            rows.append(f"<dt>Param</dt><dd>{_esc(finding.param)}</dd>")
        if finding.detail:
            rows.append(f"<dt>Detail</dt><dd>{_esc(finding.detail)}</dd>")
        if finding.remediation:
            rows.append(f"<dt>Fix</dt><dd>{_esc(finding.remediation)}</dd>")
        evidence = f"<pre>{_esc(finding.evidence)}</pre>" if finding.evidence else ""
        cards.append(
            f'<article data-sev="{sev}" style="border-left-color:{color}">'
            f'<span class="sev" style="background:{color}">{sev}</span>'
            f"<h3>{_esc(finding.title)}</h3>"
            f"<dl>{''.join(rows)}</dl>{evidence}</article>"
        )

    tech_rows = "".join(
        f"<div><b>{_esc(cat)}</b>: {_esc(', '.join(values))}</div>"
        for cat, values in sorted(ctx.tech.items())
    )
    tech_block = f'<div class="tech">{tech_rows}</div>' if tech_rows else ""

    recon_rows = []
    if ctx.subdomains:
        recon_rows.append(f"<div><b>subdomains</b>: {len(ctx.subdomains)}</div>")
    if ctx.open_ports:
        ports = ", ".join(str(p) for p, _ in sorted(ctx.open_ports))
        recon_rows.append(f"<div><b>open ports</b>: {ports}</div>")
    recon_block = f'<div class="tech">{"".join(recon_rows)}</div>' if recon_rows else ""

    filters = "".join(
        f'<button data-filter="{sev}">{sev} {counts[sev]}</button>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    body = "\n".join(cards) or '<div class="empty">No findings.</div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Akar scan report - {_esc(ctx.base_url)}</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<header>
  <h1>Akar scan report</h1>
  <div class="meta">{_esc(ctx.base_url)}<br>
    started {_esc(str(ctx.started))} &middot; duration {ctx.duration:.1f}s
    &middot; pages {len(ctx.pages)} &middot; requests {stats.get('requests', 0)}</div>
</header>
<div class="stats">
  <div class="stat"><b>{len(ctx.findings)}</b><span>findings</span></div>
  <div class="stat"><b style="color:{SEVERITY_COLORS['CRITICAL']}">{counts['CRITICAL']}</b><span>critical</span></div>
  <div class="stat"><b style="color:{SEVERITY_COLORS['HIGH']}">{counts['HIGH']}</b><span>high</span></div>
  <div class="stat"><b style="color:{SEVERITY_COLORS['MEDIUM']}">{counts['MEDIUM']}</b><span>medium</span></div>
  <div class="stat"><b style="color:{SEVERITY_COLORS['LOW']}">{counts['LOW']}</b><span>low</span></div>
  <div class="stat"><b style="color:{SEVERITY_COLORS['INFO']}">{counts['INFO']}</b><span>info</span></div>
</div>
{tech_block}{recon_block}
<div class="filters">
  <button data-filter="ALL" class="active">All</button>{filters}
</div>
<section id="list">{body}</section>
<footer>generated by akar-scan 1.0.0</footer>
</div>
<script>
document.querySelectorAll('.filters button').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const f = btn.dataset.filter;
    document.querySelectorAll('#list article').forEach(card => {{
      card.style.display = (f === 'ALL' || card.dataset.sev === f) ? '' : 'none';
    }});
  }});
}});
</script>
</body></html>"""
