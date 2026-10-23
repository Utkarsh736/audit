"""CLI - a thin wrapper around the auditor engine.

The engine is importable (`from auditor import run_audit`) so a GitHub Action,
pre-commit hook, dashboard, or VS Code extension can wrap it exactly like
this CLI does.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from . import __version__
from .engine.orchestrator import AuditOptions, explain_finding, load_last_report, run_audit
from .knowledge import rule_catalog
from .models import ALL_CATEGORIES, AuditReport, SEVERITY_WEIGHT
from .reporter import print_explanation, print_fix_result, print_report

app = typer.Typer(
    name="audit",
    help="Agentic security auditor: scan projects, explain findings, apply safe fixes.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
console_err = Console(stderr=True)

FORMAT_CHOICES = ["terminal", "json", "markdown"]
SEVERITY_CHOICES = list(SEVERITY_WEIGHT.keys())  # critical..info


def _emit(report: AuditReport, fmt: str, output: Optional[Path]) -> None:
    if fmt == "json":
        from .reporter.renderers import render_json

        text = render_json(report)
    elif fmt == "markdown":
        from .reporter.renderers import render_markdown

        text = render_markdown(report)
    else:
        print_report(report, Console())
        text = None
    if text is not None:
        if output:
            output.write_text(text, encoding="utf-8")
            console_err.print(f"[green]Report saved to {output}[/green]")
        else:
            print(text)


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Project directory or file to scan"),
    checks: str = typer.Option(
        "all", "--checks", "-c", help=f"Comma-separated checks: {', '.join(ALL_CATEGORIES)}, all"
    ),
    format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal | json | markdown"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
    min_severity: str = typer.Option("info", "--min-severity", help="Lowest severity to report"),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if findings at/above this severity exist"),
    llm: str = typer.Option("auto", "--llm", help="LLM enrichment: auto | on | off"),
    exclude: str = typer.Option("", "--exclude", "-e", help="Glob patterns to skip, comma-separated (e.g. 'tests/*,fixtures/*')"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Do not save report history"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output (stderr)"),
):
    """Scan a project and report security findings."""
    check_list = [c for c in checks.replace(" ", "").split(",") if c]
    if format not in FORMAT_CHOICES:
        console_err.print(f"[red]Unknown format '{format}'. Use: {', '.join(FORMAT_CHOICES)}[/red]")
        raise typer.Exit(2)
    if min_severity not in SEVERITY_CHOICES:
        console_err.print(f"[red]Unknown severity '{min_severity}'. Use: {', '.join(SEVERITY_CHOICES)}[/red]")
        raise typer.Exit(2)
    if llm not in ("auto", "on", "off"):
        console_err.print("[red]--llm must be auto | on | off[/red]")
        raise typer.Exit(2)

    options = AuditOptions(
        checks=check_list,
        min_severity=min_severity,
        fail_on=fail_on,
        use_llm=llm,
        save_history=not no_cache,
        excludes=[e for e in exclude.replace(" ", "").split(",") if e],
    )
    try:
        report = run_audit(path, options)
    except ValueError as e:
        console_err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    except FileNotFoundError as e:
        console_err.print(f"[red]{e}[/red]")
        raise typer.Exit(2)

    if not quiet and format == "json":
        console_err.print(
            f"[dim]Scanned {report.metadata.files_scanned} files, "
            f"{report.summary.total} findings in {report.metadata.duration_seconds}s[/dim]"
        )
    _emit(report, format, output)
    raise typer.Exit(report.exit_code(fail_on))


@app.command()
def explain(
    finding_id: str = typer.Argument(..., help="Finding ID, e.g. SECRET-001"),
    project: Optional[Path] = typer.Option(
        None, "--project", "-p", exists=True, help="Project path (default: cwd). A scan must have run."
    ),
    report_file: Optional[Path] = typer.Option(None, "--report", exists=True, help="Load a saved JSON report instead"),
    llm: bool = typer.Option(True, "--llm/--no-llm", help="Allow LLM to generate extra guidance"),
):
    """Show a detailed remediation guide for one finding."""
    project_root = (project or Path.cwd()).resolve()
    if report_file:
        try:
            report = AuditReport.model_validate_json(report_file.read_text(encoding="utf-8"))
        except Exception as e:
            console_err.print(f"[red]Invalid report file: {e}[/red]")
            raise typer.Exit(2)
        finding = report.get_finding(finding_id)
    else:
        result = explain_finding(project_root, finding_id)
        if result is None:
            console_err.print(
                f"[red]Finding '{finding_id}' not found for {project_root}.[/red]\n"
                f"Run [bold]audit scan {project_root}[/bold] first, then use the ID shown in the report."
            )
            raise typer.Exit(2)
        finding, report = result

    if finding is None:
        console_err.print(f"[red]Finding '{finding_id}' not in report.[/red]")
        raise typer.Exit(2)

    if llm and finding.llm_detail is None:
        from .llm import LLMConfig, _chat, _code_context
        from .knowledge import get_rule

        cfg = LLMConfig()
        if cfg.available:
            import json as _json

            rule = get_rule(finding.rule_id) or {}
            prompt = (
                f"You are a senior application security engineer. Explain and give a concrete fix for:\n"
                f"Finding: {finding.id} {finding.title} ({finding.severity.value})\n"
                f"File: {finding.file}:{finding.line}\nEvidence: {finding.evidence}\n"
                f"CWE: {finding.cwe}\n\nCode context:\n{_code_context(report, finding)}\n\n"
                f"KB guidance: {_json.dumps(rule.get('remediation', {}))[:800]}\n"
                f"Output markdown: why it matters, step-by-step fix for this code, verification. Max 250 words."
            )
            answer = _chat(cfg, prompt)
            if answer:
                finding.llm_detail = answer

    print_explanation(report, finding, Console())
    raise typer.Exit(0)


@app.command()
def fix(
    path: Path = typer.Argument(..., exists=True, help="Project directory"),
    finding: str = typer.Option(..., "--finding", "-F", help="Finding ID to fix, e.g. SECRET-001"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without touching anything"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply without asking"),
):
    """Apply safe, deterministic fixes (secrets -> env vars)."""
    from .fixer import apply_fix

    project_root = path.resolve()
    result = explain_finding(project_root, finding)
    if result is None:
        console_err.print(f"[red]Finding '{finding}' not found. Run a scan first.[/red]")
        raise typer.Exit(2)
    target_finding, _report = result

    if not dry_run and not yes:
        preview = apply_fix(project_root, target_finding, dry_run=True)
        console_err.print("[bold]Planned changes:[/bold]")
        for c in preview.changes:
            console_err.print(f"  - {c}")
        confirm = typer.confirm("Apply?")
        if not confirm:
            console_err.print("Aborted.")
            raise typer.Exit(0)

    fix_result = apply_fix(project_root, target_finding, dry_run=dry_run)
    print_fix_result(fix_result, Console())
    if fix_result.success:
        Console(stderr=True).print("\nRun [bold]audit scan " + str(project_root) + "[/bold] to verify.")
    raise typer.Exit(0 if fix_result.success else 1)


@app.command()
def info(
    format: str = typer.Option("terminal", "--format", help="Output format: terminal | json"),
):
    """Show engine version, available checks, and rule catalog."""
    catalog = rule_catalog()
    categories = {r["category"] for r in catalog}
    if format == "json":
        import json

        print(json.dumps({
            "tool": "auditor",
            "version": __version__,
            "checks": sorted(categories),
            "rules_count": len(catalog),
            "rules": catalog,
        }, indent=2))
        return
    console = Console()
    console.print(f"[bold]auditor[/bold] v{__version__} - {len(catalog)} rules across {len(categories)} checks")
    console.print("\n[bold]Available checks[/bold] (--checks):")
    for cat in sorted(categories):
        n = sum(1 for r in catalog if r["category"] == cat)
        console.print(f"  [cyan]{cat}[/cyan] ({n} rules)")
    console.print("\nLLM enrichment: set AUDITOR_LLM_PROVIDER + AUDITOR_LLM_API_KEY (optional).")


@app.command()
def version():
    """Print the tool version."""
    print(f"auditor {__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
