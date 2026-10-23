"""JSON and Markdown report renderers."""
from __future__ import annotations

import json

from ..models import AuditReport, Finding


def render_json(report: AuditReport, indent: int = 2) -> str:
    return json.dumps(json.loads(report.model_dump_json()), indent=indent)


def render_markdown(report: AuditReport) -> str:
    m = report.metadata
    s = report.summary
    lines = [
        "# Security Audit Report",
        "",
        f"**Project:** `{report.project_name}`  ",
        f"**Scanned:** {m.files_scanned} files, {m.lines_scanned:,} lines in {m.duration_seconds}s  ",
        f"**Checks:** {', '.join(m.checks)}  ",
        f"**Tool:** auditor v{report.version}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| CRITICAL | {s.critical} |",
        f"| HIGH | {s.high} |",
        f"| MEDIUM | {s.medium} |",
        f"| LOW | {s.low} |",
        f"| INFO | {s.info} |",
        f"| **Total** | **{s.total}** |",
        f"| **Risk score** | **{s.risk_score}/100** |",
        "",
    ]
    if m.llm_note:
        lines += [f"> {m.llm_note}", ""]

    if s.clean:
        lines += ["No findings. ", ""]
        return "\n".join(lines)

    current_sev = ""
    for f in report.findings:
        if f.severity.value != current_sev:
            current_sev = f.severity.value
            lines += [f"## {current_sev.upper()} FINDINGS", ""]
        lines += [
            f"### [{f.id}] {f.title}",
            "",
            f"- **File:** `{f.file}:{f.line}`",
            f"- **Category:** {f.category} | **CWE:** {f.cwe or '-'} | **Confidence:** {f.confidence}",
            "",
            "```",
            f"{f.evidence}",
            "```",
            "",
            f"**Impact:** {f.impact}",
            "",
            f"**Fix:** {f.quick_fix}",
            "",
        ]
        rem = f.remediation
        if rem and rem.steps:
            lines += ["**Remediation steps:**", ""]
            lines += [f"{i}. {step}" for i, step in enumerate(rem.steps, 1)]
            lines += [""]
            if rem.before and rem.after:
                lines += ["**Before**", "", "```python", rem.before, "```", "", "**After**", "", "```python", rem.after, "```", ""]
            if rem.verification:
                lines += [f"**Verify:** {rem.verification}", ""]
        if f.references:
            refs = " | ".join(f"[{r}]({r})" if r.startswith("http") else r for r in f.references[:3])
            lines += [f"**References:** {refs}", ""]
    return "\n".join(lines)
