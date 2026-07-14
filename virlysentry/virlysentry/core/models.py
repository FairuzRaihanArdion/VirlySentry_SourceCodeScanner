from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    scenario: str
    recommendation: str
    fixed_example: str
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label(),
            "file": self.file_path,
            "line": self.line_number,
            "column": self.column,
            "code_snippet": self.code_snippet,
            "scenario": self.scenario,
            "recommendation": self.recommendation,
            "fixed_example": self.fixed_example,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
        }


@dataclass
class DeadCodeFinding:
    kind: str
    name: str
    file_path: str
    line_number: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "file": self.file_path,
            "line": self.line_number,
            "reason": self.reason,
        }


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    dead_code: List[DeadCodeFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0

    def severity_counts(self) -> dict:
        counts = {s.label(): 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label()] += 1
        return counts

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "duration_seconds": round(self.duration_seconds, 3),
                "total_findings": len(self.findings),
                "severity_counts": self.severity_counts(),
                "dead_code_count": len(self.dead_code),
            },
            "findings": [f.to_dict() for f in self.findings],
            "dead_code": [d.to_dict() for d in self.dead_code],
        }
