"""Finding model and severity helpers."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITIES = ["critical", "high", "medium", "low", "info", "pass"]

# Points deducted from 100 per finding of each severity.
PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0, "pass": 0}


@dataclass
class Finding:
    id: str                 # stable machine id, e.g. "header.csp.missing"
    title: str
    category: str           # headers | transport | cookies | cors | content | disclosure | exposure
    severity: str           # one of SEVERITIES
    description: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: Optional[str] = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def passed(id: str, title: str, category: str, evidence: str | None = None) -> Finding:
    return Finding(id=id, title=title, category=category, severity="pass", evidence=evidence)
