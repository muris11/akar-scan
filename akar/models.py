from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Input:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    action: str
    method: str = "GET"
    inputs: list[Input] = field(default_factory=list)

    @property
    def names(self) -> list[str]:
        return [i.name for i in self.inputs if i.name]

    def has_file(self) -> bool:
        return any(i.type == "file" for i in self.inputs)


@dataclass
class Page:
    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    body: str = ""
    content_type: str = ""
    elapsed: float = 0.0
    depth: int = 0
    forms: list[Form] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)
    error: str = ""
    from_robots: bool = False

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def title(self) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", self.body[:8192], re.I | re.S)
        return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""

    @property
    def is_html(self) -> bool:
        ct = self.content_type.lower()
        if "html" in ct:
            return True
        return not ct and self.body.lstrip()[:1] in ("", "<")


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    url: str = ""
    param: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.id, self.url, self.param)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "url": self.url,
            "param": self.param,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "extra": self.extra,
        }
