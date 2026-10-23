"""Deduplication, severity ranking, and stable finding-ID assignment."""
from __future__ import annotations

from ..models import CATEGORY_PREFIX, Finding, SEVERITY_WEIGHT


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate and near-duplicate findings.

    Exact: same rule + file + line.
    Near: same rule + file within +/-2 lines (multi-pattern hits).
    """
    exact: dict[tuple[str, str, int], Finding] = {}
    for f in findings:
        f.compute_fingerprint()
        key = (f.rule_id, f.file, f.line)
        if key not in exact:
            exact[key] = f

    result: list[Finding] = list(exact.values())
    near: dict[str, list[Finding]] = {}
    for f in result:
        near.setdefault(f"{f.rule_id}|{f.file}", []).append(f)

    deduped: list[Finding] = []
    for group in near.values():
        group.sort(key=lambda f: f.line)
        kept_lines: list[int] = []
        for f in group:
            if any(abs(f.line - k) <= 1 for k in kept_lines):
                continue
            kept_lines.append(f.line)
            deduped.append(f)
    return deduped


def rank_and_assign_ids(findings: list[Finding]) -> list[Finding]:
    """Sort by severity, then file, then line; assign CATEGORY-NNN display IDs.

    Deterministic ordering means the same code always yields the same IDs,
    which keeps `audit explain SECRET-001` stable across runs and lets CI
    track findings by fingerprint.
    """
    findings.sort(
        key=lambda f: (
            SEVERITY_WEIGHT[f.severity.value],
            f.file,
            f.line,
            f.rule_id,
        )
    )
    counters: dict[str, int] = {}
    for f in findings:
        prefix = CATEGORY_PREFIX.get(f.category, "FIND")
        counters[prefix] = counters.get(prefix, 0) + 1
        f.id = f"{prefix}-{counters[prefix]:03d}"
    return findings


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_WEIGHT.get(min_severity, 4)
    return [f for f in findings if SEVERITY_WEIGHT[f.severity.value] <= threshold]
