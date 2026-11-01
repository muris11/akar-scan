from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from datetime import datetime

from . import __version__


class Progress:
    """Single-line progress printer on stderr (no-op when not a TTY)."""

    def __init__(self) -> None:
        self.tty = sys.stderr.isatty()
        self.shown = False

    def __call__(self, message: str) -> None:
        if not self.tty:
            return
        line = f"\r\x1b[2K{message[:110]}"
        sys.stderr.write(line)
        sys.stderr.flush()
        self.shown = True

    def done(self) -> None:
        if self.shown and self.tty:
            sys.stderr.write("\r\x1b[2K")
            sys.stderr.flush()
            self.shown = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="akar",
        description="Akar - deep web application scanner (recon + crawl + vuln checks).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL (scheme optional, e.g. example.com)")
    parser.add_argument("--version", action="version", version=f"akar {__version__}")

    grp = parser.add_argument_group("crawling")
    grp.add_argument("--depth", type=int, default=3, help="max crawl depth")
    grp.add_argument("--max-pages", type=int, default=120, help="max pages to crawl")
    grp.add_argument("--no-js", action="store_true", help="do not extract links from inline JS")
    grp.add_argument("--robots", action="store_true", help="also crawl paths disallowed in robots.txt")
    grp.add_argument("--max-test-pages", type=int, default=25, help="pages sampled for active tests")

    grp = parser.add_argument_group("requests")
    grp.add_argument("--threads", type=int, default=20, help="concurrent requests")
    grp.add_argument("--timeout", type=float, default=10.0, help="request timeout (seconds)")
    grp.add_argument("--rate", type=float, default=0.0, help="requests/sec per host (0 = unlimited)")
    grp.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    grp.add_argument("--header", action="append", metavar="K:V", help="custom header (repeatable)")
    grp.add_argument("--cookie", help="Cookie header value")
    grp.add_argument("--auth", metavar="USER:PASS", help="HTTP basic auth")
    grp.add_argument("--user-agent", default=f"AkarScan/{__version__} (+security-scanner)")
    grp.add_argument("--insecure", action="store_true", help="skip TLS verification")
    grp.add_argument("--no-http2", action="store_true", help="disable HTTP/2")

    grp = parser.add_argument_group("recon")
    grp.add_argument("--subdomains", action="store_true", help="enumerate subdomains (crt.sh + DNS brute)")
    grp.add_argument("--no-crt", action="store_true", help="skip crt.sh during subdomain enumeration")
    grp.add_argument(
        "--ports",
        nargs="?",
        const=True,
        default=None,
        help="ports to scan, e.g. 80,443,8000-8100 (bare flag = common list)",
    )
    grp.add_argument("--port-timeout", type=float, default=1.2, help="port probe timeout")

    grp = parser.add_argument_group("active tests")
    grp.add_argument("--max-tests", type=int, default=500, help="budget of active test requests")
    grp.add_argument("--sqli-aggressive", action="store_true", help="enable time-based SQLi probes (slow)")
    grp.add_argument("--test-forms", action="store_true", help="include HTML forms in injection tests")
    grp.add_argument("--only", help="run only these modules (comma separated ids)")
    grp.add_argument("--skip", help="skip these modules (comma separated ids)")
    grp.add_argument("--list-modules", action="store_true", help="list available modules and exit")

    grp = parser.add_argument_group("output")
    grp.add_argument("--format", default="console", help="outputs: console,json,html (comma separated)")
    grp.add_argument("-o", "--output", help="output file prefix (default: akar-<host>-<time>)")
    grp.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                     help="exit non-zero if a finding at/above this severity exists")
    grp.add_argument("-v", "--verbose", action="store_true", help="debug logging on stderr")
    return parser


def _list_modules() -> None:
    from .checks import ALL_CHECKS, RECON_MODULES

    print("Available modules:")
    print("  id                 name")
    print("  " + "-" * 60)
    for check in ALL_CHECKS:
        print(f"  {check.id:<18} {check.name}")
    for module_id, description in RECON_MODULES:
        print(f"  {module_id:<18} {description}")


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        _list_modules()
        return

    if not args.url:
        parser.error("target url is required")

    args.only = [x for x in (args.only or "").split(",") if x.strip()]
    args.skip = [x for x in (args.skip or "").split(",") if x.strip()]
    args.parse_js = not args.no_js
    args.crt = not args.no_crt

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    progress = Progress()
    args.progress = progress

    from .engine import run_scan

    try:
        ctx = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        progress.done()
        sys.stderr.write("\ninterrupted\n")
        raise SystemExit(130)
    except RuntimeError as exc:
        progress.done()
        sys.stderr.write(f"error: {exc}\n")
        raise SystemExit(2)
    finally:
        progress.done()

    outputs = [x.strip().lower() for x in (args.format or "console").split(",") if x.strip()]

    if "console" in outputs or not outputs:
        from .reporting import console

        sys.stdout.write(console.render(ctx))

    written: list[str] = []
    if "json" in outputs or "html" in outputs:
        from .reporting import htmlout, jsonout

        if args.output:
            prefix = args.output
        else:
            from .utils import host_of

            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            prefix = f"akar-{host_of(ctx.base_url).replace('.', '_')}-{stamp}"

        if "json" in outputs:
            path = prefix + ".json"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(jsonout.render(ctx))
            written.append(path)
        if "html" in outputs:
            path = prefix + ".html"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(htmlout.render(ctx))
            written.append(path)

    for path in written:
        print(f"report written: {path}")

    if args.fail_on:
        from .models import Severity

        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in ctx.findings):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
