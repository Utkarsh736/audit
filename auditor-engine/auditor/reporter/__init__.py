"""Terminal reporter - rich-formatted, human-friendly output."""
from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import AuditReport, Finding

SEV_STYLE = {
    "critical": ("bold red", "CRITICAL", "\u25cf"),
    "high": ("bold yellow", "HIGH", "\u25cf"),
    "medium": ("yellow", "MEDIUM", "\u25cb"),
    "low": ("cyan", "LOW", "\u25cb"),
    "info": ("dim", "INFO", "\u25cb"),
}


def _sev(f: Finding) -> tuple[str, str, str]:
    return SEV_STYLE.get(f.severity.value, ("white", "INFO", "-"))


def print_report(report: AuditReport, console: Console | None = None, verbose: bool = False) -> None:
    console = console or Console()
    m = report.metadata
    header = Table.grid(padding=(0, 2))
    header.add_row(Text("\U0001F512  Security Audit Report", style="bold white", justify="center"))
    header.add_row(Text(f"Project: {report.project_name}", style="dim"))
    header.add_row(
        Text(
            f"Scanned: {m.files_scanned} files | {m.lines_scanned:,} lines | "
            f"{m.duration_seconds}s | checks: {', '.join(m.checks)}",
            style="dim",
        )
    )
    console.print(Panel(header, border_style="blue", expand=False))

    s = report.summary
    if s.clean:
        console.print(Panel(Text("No findings. Nice.\n", style="bold green"), title="Result", border_style="green"))
        _print_llm_note(report, console)
        return

    summary = Table.grid(padding=(0, 3))
    row = []
    for key, color in (("critical", "red"), ("high", "yellow"), ("medium", "yellow"), ("low", "cyan"), ("info", "dim")):
        n = getattr(s, key)
        if n:
            row.append(Text(f"{n} {key.upper()}", style=f"bold {color}"))
    row.append(Text(f"risk {s.risk_score}/100", style="bold white"))
    summary.add_row(*row)
    console.print(Panel(summary, title="Summary", border_style="blue"))
    _print_llm_note(report, console)

    for f in report.findings:
        style, label, icon = _sev(f)
        title = Text(f"{icon} {label}  [{f.id}]  {f.title}", style=style)
        body = Table.grid(padding=(0, 1))
        body.add_row(Text(f"File: {f.file}:{f.line}", style="bold"))
        body.add_row(Text("Evidence:", style="dim"))
        body.add_row(Text(f"  {f.evidence}", style="white on #1c1c1c"))
        if f.impact:
            body.add_row(Text("Impact:", style="dim"))
            wrapped = "\n".join(_wrap(f.impact, 72, 2) for _ in [0])
            body.add_row(Text(wrapped))
        if f.quick_fix:
            body.add_row(Text(f"Fix: {f.quick_fix}", style="green"))
        if f.confidence != "high":
            body.add_row(Text(f"confidence: {f.confidence} (heuristic - review recommended)", style="dim"))
        hint = f"Run `audit explain {f.id}` for the full remediation guide"
        if f.auto_fixable:
            hint += f" | `audit fix --finding {f.id} <project>` can auto-fix"
        body.add_row(Text(hint, style="italic dim"))
        console.print()
        console.print(Panel(body, title=title, title_align="left", border_style=style.split()[-1], expand=False))


def _wrap(text: str, width: int, indent: int) -> str:
    import textwrap

    return "\n".join(textwrap.wrap(text, width=width, initial_indent=" " * indent, subsequent_indent=" " * indent))


def _print_llm_note(report: AuditReport, console: Console) -> None:
    if report.metadata.llm_note:
        console.print(Text(f"  {report.metadata.llm_note}", style="dim italic"))


def print_explanation(report: AuditReport, finding: Finding, console: Console | None = None) -> None:
    console = console or Console()
    style, label, _ = _sev(finding)

    header = Table.grid(padding=(0, 1))
    header.add_row(Text(f"{label} {finding.id} - {finding.title}", style=style))
    header.add_row(Text(f"{finding.file}:{finding.line}  |  {finding.tool_source}  |  confidence: {finding.confidence}", style="dim"))
    console.print(Panel(header, border_style=style.split()[-1]))

    if finding.description:
        console.print(Text("Why this is a problem", style="bold underline"))
        console.print(Text(_wrap(finding.description, 90, 0)))
        console.print()
    if finding.evidence:
        console.print(Text("Evidence", style="bold underline"))
        console.print(Text(f"  {finding.evidence}", style="white on #1c1c1c"))
        console.print()
    if finding.impact:
        console.print(Text("Impact", style="bold underline"))
        console.print(Text(_wrap(finding.impact, 90, 0)))
        console.print()

    refs = []
    if finding.cwe:
        refs.append(finding.cwe)
    refs.extend(finding.owasp or [])
    if refs:
        console.print(Text("References: " + ", ".join(refs), style="cyan"))
        for r in finding.references[:4]:
            console.print(Text(f"  {r}", style="dim cyan"))
        console.print()

    rem = finding.remediation
    if rem and rem.steps:
        console.print(Text("How to fix it", style="bold underline green"))
        for i, step in enumerate(rem.steps, 1):
            console.print(Text(f"  {i}. {step}"))
        console.print()
        if rem.before or rem.after:
            console.print(Text("  Before:", style="dim"))
            for line in (rem.before or "").splitlines():
                console.print(Text(f"    {line}", style="red"))
            console.print(Text("  After:", style="dim"))
            for line in (rem.after or "").splitlines():
                console.print(Text(f"    {line}", style="green"))
            console.print()
        if rem.verification:
            console.print(Text("Verification", style="bold underline"))
            console.print(Text(f"  {rem.verification}", style="cyan"))
            console.print()

    if finding.llm_detail:
        console.print(Text("AI-generated guidance (review before applying)", style="bold underline magenta"))
        from rich.markdown import Markdown

        console.print(Markdown(finding.llm_detail))
        console.print()


def print_fix_result(result, console: Console | None = None) -> None:
    console = console or Console()
    if result.error:
        console.print(Text(f"  \u2717 Failed: {result.error}", style="bold red"))
        return
    if result.success:
        console.print(Text(f"  Applied fix for {result.finding_id}:", style="bold green"))
        for c in result.changes:
            console.print(Text(f"  \u2713 {c}", style="green"))
    else:
        console.print(Text(f"  No automatic fix available for {result.finding_id}.", style="yellow"))
    if result.manual_actions:
        console.print(Text("  \u26a0  Manual action required:", style="bold yellow"))
        for ma in result.manual_actions:
            console.print(Text(f"     {ma}", style="yellow"))
