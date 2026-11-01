from __future__ import annotations

import re

from ..models import Finding, Page, Severity
from ..utils import build_url, similarity
from .base import Check
from .common import spend, testable_params

ERROR_SIGNATURES = [
    ("MySQL", re.compile(
        r"you have an error in your sql syntax|warning:\s*mysql_|mysqli?_|"
        r"supplied argument is not a valid mysql|mysql_fetch_array|"
        r"check the manual that corresponds to your (?:mariadb|mysql)", re.I)),
    ("MSSQL", re.compile(
        r"microsoft oledb provider for sql server|unclosed quotation mark after the|"
        r"system\.data\.sqlexception|incorrect syntax near|Microsoft OLE DB Provider", re.I)),
    ("PostgreSQL", re.compile(
        r"pg_query\(\)|unterminated quoted string at or near|PG::SyntaxError|"
        r"pg_exec\(|Npgsql\.", re.I)),
    ("Oracle", re.compile(r"ORA-\d{5}|quoted string not properly terminated|oracle error", re.I)),
    ("SQLite", re.compile(
        r"SQLite/JDBCDriver|sqlite3\.(?:Operational|Database)Error|SQL logic error|"
        r"malformed database schema|sqlite error", re.I)),
    ("Generic", re.compile(
        r"\bSQLSTATE\[[0-9A-Z]+\]|valid MySQL result|Unknown column '[^']+' in 'field list'|"
        r"syntax error.*?\bquery\b|mysql_num_rows|supplied argument is not a valid", re.I)),
]

TIME_PAYLOADS = [
    ("MySQL", "1' OR SLEEP(5)-- -", 4.5),
    ("MSSQL", "1'; WAITFOR DELAY '0:0:5'-- -", 4.5),
    ("PostgreSQL", "1' OR pg_sleep(5)-- -", 4.5),
    ("Oracle", "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- -", 4.5),
]


class SqliCheck(Check):
    id = "sqli"
    name = "SQL injection (error & boolean blind)"
    description = "Error-signature and boolean-differential probes on query parameters."

    async def on_page(self, ctx, page: Page) -> None:
        if not page.ok or not page.url:
            return
        tested: set[str] = ctx.state.setdefault("sqli_params_tested", set())
        for param in testable_params(page, limit=4):
            key = f"{page.url}|{param}"
            if key in tested or not spend(ctx):
                continue
            tested.add(key)
            original = _current_value(page, param)
            await self._error_probe(ctx, page, param, original)
            await self._boolean_probe(ctx, page, param, original)
        if ctx.args.sqli_aggressive:
            await self._time_probe(ctx, page)

    async def _error_probe(self, ctx, page: Page, param: str, original: str) -> None:
        for payload in (original + "'", original + '"', original + "\\", "1'"):
            if not spend(ctx):
                return
            resp = await ctx.client.get(build_url(page.url, param, payload))
            if resp.error or not resp.body:
                continue
            for engine, pattern in ERROR_SIGNATURES:
                match = pattern.search(resp.body[:400_000])
                if match:
                    ctx.add(Finding(
                        id="sqli-error",
                        title=f"SQL error disclosure via '{param}' ({engine})",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        param=param,
                        detail="A crafted value triggers a database error message in the response.",
                        evidence=_clip(resp.body[max(0, match.start() - 80): match.end() + 120]),
                        remediation="Use parameterized queries; disable verbose DB errors in production.",
                    ))
                    return

    async def _boolean_probe(self, ctx, page: Page, param: str, original: str) -> None:
        base_body = page.body
        if not base_body or len(base_body) < 50:
            return

        variants = [
            (original + "' AND '1'='1", original + "' AND '1'='2"),
            (original + " AND 1=1", original + " AND 1=2"),
            (original + "' AND '1'='1'-- -", original + "' AND '1'='2'-- -"),
        ]
        for true_payload, false_payload in variants:
            if not spend(ctx, 2):
                return
            resp_true = await ctx.client.get(build_url(page.url, param, true_payload))
            resp_false = await ctx.client.get(build_url(page.url, param, false_payload))
            if resp_true.error or resp_false.error:
                continue
            if resp_true.status != resp_false.status:
                continue
            if resp_true.status not in (200, 500) or resp_false.status not in (200, 500):
                continue
            len_true, len_false, len_base = len(resp_true.body), len(resp_false.body), len(base_body)
            if len_true == 0 or len_false == 0:
                continue

            true_close = (
                abs(len_true - len_base) < max(300, int(len_base * 0.10))
                or similarity(resp_true.body, base_body) > 0.90
            )
            false_diverges = (
                abs(len_false - len_true) > max(300, int(max(len_true, len_false) * 0.15))
                or similarity(resp_false.body, base_body) < 0.75
            )
            false_differs_from_true = abs(len_false - len_true) > max(200, int(len_true * 0.10))
            if true_close and false_diverges and false_differs_from_true:
                ctx.add(Finding(
                    id="sqli-blind-boolean",
                    title=f"Boolean-based blind SQL injection via '{param}'",
                    severity=Severity.HIGH,
                    url=page.url,
                    param=param,
                    detail=(
                        "True/false payloads produce consistently different responses while the "
                        "true variant matches the baseline, indicating a conditional in the query."
                    ),
                    evidence=(
                        f"baseline={len_base}b, true={len_true}b, false={len_false}b; "
                        f"payloads: '{true_payload[:40]}' vs '{false_payload[:40]}'"
                    ),
                    remediation="Use parameterized queries / prepared statements for all inputs.",
                ))
                return

    async def _time_probe(self, ctx, page: Page) -> None:
        import time as _time

        tested: set[str] = ctx.state.setdefault("sqli_time_tested", set())
        for param in testable_params(page, limit=2):
            if param in tested:
                continue
            tested.add(param)
            original = _current_value(page, param)
            for _engine, payload, threshold in TIME_PAYLOADS:
                if not spend(ctx):
                    return
                start = _time.perf_counter()
                resp = await ctx.client.get(
                    build_url(page.url, param, original + payload), timeout=ctx.args.timeout + 8
                )
                elapsed = _time.perf_counter() - start
                if not resp.error and elapsed >= threshold:
                    ctx.add(Finding(
                        id="sqli-time-blind",
                        title=f"Time-based blind SQL injection via '{param}'",
                        severity=Severity.HIGH,
                        url=page.url,
                        param=param,
                        detail="The response was delayed by the injected time function.",
                        evidence=f"payload={payload[:50]}; elapsed={elapsed:.1f}s",
                        remediation="Use parameterized queries; ensure all inputs are bound, not concatenated.",
                    ))
                    return


def _current_value(page: Page, param: str) -> str:
    from urllib.parse import parse_qsl, urlsplit

    for key, value in parse_qsl(urlsplit(page.url).query, keep_blank_values=True):
        if key == param:
            return value
    return ""


def _clip(text: str, size: int = 240) -> str:
    return re.sub(r"\s+", " ", text).strip()[:size]
