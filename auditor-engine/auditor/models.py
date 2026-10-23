"""Data models for the security auditor.

Every issue is a structured Finding object (not free text), so reports can be
rendered as terminal output, JSON (CI/CD), Markdown (PR comments) or HTML
(dashboard) from the same data.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
ConfidenceLevel = Literal["high", "medium", "low"]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# Weighted risk score contribution per finding.
RISK_WEIGHT: dict[str, int] = {
    "critical": 15,
    "high": 7,
    "medium": 3,
    "low": 1,
    "info": 0,
}

# Category -> human-facing finding-ID prefix (SECRET-001, PROMPT-003, ...)
CATEGORY_PREFIX: dict[str, str] = {
    "secrets": "SECRET",
    "prompt-injection": "PROMPT",
    "data-handling": "DATA",
    "auth": "AUTH",
    "insecure-output": "OUTPUT",
    "dangerous-code": "CODE",
    "configuration": "CONFIG",
}

ALL_CATEGORIES = list(CATEGORY_PREFIX.keys())


class Remediation(BaseModel):
    """Actionable fix guidance attached to a finding from the knowledge base."""

    steps: list[str] = Field(default_factory=list)
    before: Optional[str] = None
    after: Optional[str] = None
    verification: Optional[str] = None


class Finding(BaseModel):
    """A single, structured security finding."""

    id: str = ""  # Display ID, e.g. "SECRET-001" (assigned after ranking)
    rule_id: str  # Stable KB rule ID, e.g. "secret.groq_key"
    severity: Severity
    category: str  # secrets | prompt-injection | data-handling | auth | ...
    title: str
    file: str  # Path relative to the scanned project root
    line: int
    end_line: int = 0
    evidence: str  # Masked code snippet (secrets are never echoed in full)
    description: str = ""
    impact: str = ""
    quick_fix: str = ""
    remediation: Optional[Remediation] = None
    references: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    owasp: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel = "medium"
    tool_source: str = "built-in"
    fingerprint: str = ""  # Stable hash for dedupe / tracking across runs
    auto_fixable: bool = False
    llm_detail: Optional[str] = None  # Optional LLM-generated deep guidance

    def compute_fingerprint(self) -> str:
        raw = f"{self.rule_id}|{self.file}|{self.line}|{self.evidence[:64]}"
        self.fingerprint = hashlib.sha1(raw.encode()).hexdigest()[:12]
        return self.fingerprint

    def to_compact(self) -> dict[str, Any]:
        """Compact view used by the `audit explain` terminal renderer."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "file": self.file,
            "line": self.line,
        }


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0
    risk_score: int = 0  # 0-100
    clean: bool = True

    @staticmethod
    def from_findings(findings: list[Finding]) -> "ScanSummary":
        counts = {k: 0 for k in SEVERITY_WEIGHT}
        for f in findings:
            counts[f.severity.value] += 1
        raw_score = sum(RISK_WEIGHT[f.severity.value] for f in findings)
        return ScanSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            total=len(findings),
            risk_score=min(100, raw_score),
            clean=len(findings) == 0,
        )


class ScanMetadata(BaseModel):
    started_at: str = ""
    duration_seconds: float = 0.0
    checks: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    lines_scanned: int = 0
    languages: dict[str, int] = Field(default_factory=dict)
    tool_version: str = ""
    llm_enriched: bool = False
    llm_note: str = ""


class AuditReport(BaseModel):
    tool: str = "auditor"
    version: str = "0.1.0"
    project_path: str = ""
    project_name: str = ""
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[Finding] = Field(default_factory=list)

    def exit_code(self, fail_on: str = "high") -> int:
        """0 = clean, 1 = findings at/above threshold. This is what makes the
        tool usable in CI/CD pipelines and pre-commit hooks."""
        threshold = SEVERITY_WEIGHT.get(fail_on, 1)
        for f in self.findings:
            if SEVERITY_WEIGHT[f.severity.value] <= threshold:
                return 1
        return 0

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        for f in self.findings:
            if f.id.upper() == finding_id.upper() or f.fingerprint == finding_id:
                return f
        return None


class FixResult(BaseModel):
    finding_id: str
    success: bool
    changes: list[str] = Field(default_factory=list)
    manual_actions: list[str] = Field(default_factory=list)
    error: Optional[str] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
