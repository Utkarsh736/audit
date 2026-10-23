"""Orchestrator - the audit pipeline.

Deterministic by design (CI-friendly, reproducible, no LLM in the detection
path):

    1. Discover files        -> walk the project, identify languages
    2. Run scanners          -> regex + AST detectors (optionally in parallel)
    3. Collect raw findings  -> structured objects
    4. Deduplicate + rank    -> merge, sort by severity, assign stable IDs
    5. Enrich from KB        -> attach CWE/OWASP references + remediation
    6. LLM enrichment        -> OPTIONAL: deeper guidance (never detection)
    7. Build report          -> terminal / JSON / markdown renderers
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .. import __version__
from ..knowledge import enrich as enrich_from_kb
from ..models import ALL_CATEGORIES, AuditReport, Finding, ScanMetadata, ScanSummary, Severity, utc_now_iso
from ..scanners import get_scanners, scan_project
from .dedupe import dedupe, filter_by_severity, rank_and_assign_ids
from .discovery import count_languages, discover_files

AUDITOR_HOME = Path.home() / ".auditor"
CACHE_DIR = AUDITOR_HOME / "cache"
HISTORY_DIR = AUDITOR_HOME / "history"


class AuditOptions:
    def __init__(
        self,
        checks: list[str] | None = None,
        min_severity: str = "info",
        fail_on: str = "high",
        use_llm: str = "auto",  # auto | on | off
        save_history: bool = True,
        max_llm_findings: int = 10,
        excludes: list[str] | None = None,
    ):
        self.checks = checks or list(ALL_CATEGORIES)
        self.min_severity = min_severity
        self.fail_on = fail_on
        self.use_llm = use_llm
        self.save_history = save_history
        self.max_llm_findings = max_llm_findings
        self.excludes = excludes or []


def project_cache_path(project_root: Path) -> Path:
    digest = hashlib.sha1(str(project_root.resolve()).encode()).hexdigest()[:10]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{digest}.json"


def save_report(report: AuditReport, project_root: Path, history: bool) -> None:
    """Persist the report: a per-project 'last report' cache (for `audit
    explain`) plus an append-only history entry."""
    try:
        cache = project_cache_path(project_root)
        cache.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        if history:
            HISTORY_DIR.mkdir(parents=True, exist_ok=True)
            ts = report.metadata.started_at.replace(":", "").replace("-", "")[:15]
            name = Path(report.project_path).name.replace(" ", "_")
            entry = HISTORY_DIR / f"{ts}_{name}.json"
            entry.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    except OSError:
        pass


def load_last_report(project_root: Path) -> AuditReport | None:
    cache = project_cache_path(project_root)
    if not cache.exists():
        return None
    try:
        return AuditReport.model_validate_json(cache.read_text(encoding="utf-8"))
    except Exception:
        return None


def run_audit(target: str | Path, options: AuditOptions | None = None) -> AuditReport:
    """Execute a full audit. This is the single entry point the CLI, the
    dashboard API, and future integrations (GitHub Action, pre-commit) call."""
    options = options or AuditOptions()
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {root}")
    if not root.is_dir():
        root = root.parent

    started = time.perf_counter()
    started_at = utc_now_iso()

    files = discover_files(root, options.excludes)
    scanners = get_scanners(options.checks)

    raw_findings = scan_project(root, scanners, [(f.path, f.language) for f in files])

    findings = rank_and_assign_ids(dedupe(raw_findings))
    findings = [enrich_from_kb(f) for f in findings]
    findings = filter_by_severity(findings, options.min_severity)

    report = AuditReport(
        version=__version__,
        project_path=str(root),
        project_name=root.name,
        metadata=ScanMetadata(
            started_at=started_at,
            duration_seconds=round(time.perf_counter() - started, 2),
            checks=options.checks,
            files_scanned=len(files),
            lines_scanned=sum(f.lines for f in files),
            languages=count_languages(files),
            tool_version=__version__,
        ),
        summary=ScanSummary.from_findings(findings),
        findings=findings,
    )

    # Optional LLM enrichment (guidance only - never detection)
    if options.use_llm != "off":
        from ..llm import enrich_report

        enrich_report(report, options)

    if options.save_history:
        save_report(report, root, history=True)
    return report


def explain_finding(project_root: Path, finding_id: str) -> tuple[Finding, AuditReport] | None:
    """Resolve a finding ID against the cached (or freshly re-run) report."""
    report = load_last_report(project_root)
    if report is None:
        report = run_audit(project_root, AuditOptions(save_history=False))
    finding = report.get_finding(finding_id)
    if finding is None:
        return None
    return finding, report
