from __future__ import annotations

import json
from datetime import datetime, timezone


def to_dict(ctx) -> dict:
    stats = ctx.client.stats if ctx.client else {}
    return {
        "tool": "akar-scan",
        "version": "1.0.0",
        "target": ctx.base_url,
        "started": datetime.fromtimestamp(ctx.started, tz=timezone.utc).isoformat(),
        "duration_seconds": round(ctx.duration, 2),
        "stats": {
            "pages": len(ctx.pages),
            "requests": stats.get("requests", 0),
            "errors": stats.get("errors", 0),
            "bytes": stats.get("bytes", 0),
            "test_requests": ctx.state.get("test_requests", 0),
        },
        "counts": ctx.counts(),
        "technologies": dict(ctx.tech),
        "tls": {k: v for k, v in ctx.tls.items() if k != "subjectAltName"},
        "subdomains": ctx.subdomains,
        "open_ports": [{"port": p, "banner": b} for p, b in sorted(ctx.open_ports)],
        "robots_paths": sorted(ctx.robots_paths),
        "findings": [f.to_dict() for f in ctx.findings],
    }


def render(ctx) -> str:
    return json.dumps(to_dict(ctx), indent=2, ensure_ascii=False, default=str)
