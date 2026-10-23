"""Safe auto-fixer.

Only deterministic, reversible fixes are ever applied automatically:
moving hardcoded secrets to .env + rewriting the code line to read the
environment variable. Everything else stays a recommendation (shown as a
diff) because auto-editing auth/prompt logic is not safe.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, FixResult
from ..knowledge import get_rule

# Matches: api_key="...", api_key='...', api_key: "...", token = '...'
ASSIGN_RE = re.compile(
    r"""(?ix)(?P<prefix>
        (?P<name>api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?key|
             secret|token|password|passwd|auth[_\-]?token)
        \s*[:=]\s*
    )(?P<q>["'])(?P<val>[^"'\n]{8,})(?P=q)"""
)


def _find_value_on_line(line: str) -> tuple[str, str] | None:
    """Return (quoted_match, value) if the line assigns a literal secret."""
    m = ASSIGN_RE.search(line)
    if m:
        return m.group(0), m.group("val")
    # direct positional: Groq(api_key="...")
    m2 = re.search(r"""(?ix)(?P<name>api[_\-]?key|token|secret)\s*=\s*(?P<q>["'])(?P<val>[^"'\n]{8,})(?P=q)""", line)
    if m2:
        return m2.group(0), m2.group("val")
    return None


def _mask(value: str) -> str:
    return f"{value[:4]}...{value[-2:]}" if len(value) > 8 else "***"


def propose_fix(project_root: Path, finding: Finding) -> FixResult:
    """Preview the fix without touching anything."""
    rule = get_rule(finding.rule_id) or {}
    if rule.get("auto_fix") != "env_var":
        return FixResult(
            finding_id=finding.id,
            success=False,
            changes=[],
            manual_actions=["No safe auto-fix available for this finding - follow the remediation steps manually."],
        )
    target = project_root / finding.file
    if not target.exists():
        return FixResult(finding_id=finding.id, success=False, error=f"File not found: {finding.file}")
    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as e:
        return FixResult(finding_id=finding.id, success=False, error=str(e))

    line_text = lines[finding.line - 1] if finding.line <= len(lines) else ""
    match = _find_value_on_line(line_text)
    if not match:
        return FixResult(
            finding_id=finding.id,
            success=False,
            manual_actions=["The assignment is not a simple literal - apply the fix manually."],
        )

    env_var = rule.get("env_var") or "SECRET_KEY"
    return FixResult(
        finding_id=finding.id,
        success=True,
        changes=[
            f"Replace the literal on {finding.file}:{finding.line} with os.environ[\"{env_var}\"] (or os.getenv)",
            f"Append {env_var}=<value {_mask(match[1])}> to .env",
            "Ensure .env is listed in .gitignore",
        ],
        manual_actions=[
            f"Rotate the exposed credential ({env_var}) - it must be treated as compromised."
            + (f" Console: {rule.get('env_var_hint')}" if rule.get("env_var_hint") else "")
        ],
    )


def apply_fix(project_root: Path, finding: Finding, dry_run: bool = False) -> FixResult:
    """Apply the env-var migration for a secret finding."""
    preview = propose_fix(project_root, finding)
    if not preview.success:
        return preview

    rule = get_rule(finding.rule_id) or {}
    env_var = rule.get("env_var") or "SECRET_KEY"
    target = (project_root / finding.file).resolve()
    content = target.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    line_text = lines[finding.line - 1]

    match = _find_value_on_line(line_text)
    if not match:
        return preview

    full_match, value = match

    # 1) build the replacement expression for this language
    if target.suffix == ".py":
        replacement = full_match.replace(f'"{value}"', f'os.environ["{env_var}"]').replace(
            f"'{value}'", f'os.environ["{env_var}"]'
        )
        needs_import = "import os" not in content and "from os" not in content
    else:  # JS family
        replacement = full_match.replace(f'"{value}"', f'process.env.{env_var}').replace(
            f"'{value}'", f'process.env.{env_var}'
        )
        needs_import = False

    if dry_run:
        return FixResult(
            finding_id=finding.id,
            success=True,
            changes=preview.changes + [f"DRY RUN - would rewrite {finding.file}:{finding.line} -> {replacement.strip()[:120]}"],
            manual_actions=preview.manual_actions,
        )

    changes: list[str] = []

    # 2) rewrite the code line
    lines[finding.line - 1] = line_text.replace(full_match, replacement)
    new_content = "\n".join(lines)
    if needs_import:
        # insert `import os` after any shebang/docstring - simplest: after first import or at top
        insert_at = 0
        for i, l in enumerate(lines[:40]):
            if l.startswith(("import ", "from ")):
                insert_at = i + 1
                break
        new_content = "\n".join(lines[:insert_at] + ["import os"] + lines[insert_at:])
        changes.append("Added 'import os' to the file")
    target.write_text(new_content, encoding="utf-8")
    changes.append(f"Modified {finding.file} (line {finding.line}) to read {env_var} from the environment")

    # 3) append to .env
    env_path = project_root / ".env"
    env_path.touch(exist_ok=True)
    existing = env_path.read_text(encoding="utf-8", errors="ignore")
    entry = f"{env_var}={value}"
    if env_var not in existing:
        with open(env_path, "a", encoding="utf-8") as fh:
            fh.write(("" if existing.endswith("\n") or not existing else "\n") + entry + "\n")
        changes.append(f"Created/updated .env with {env_var} (value: {_mask(value)})")

    # 4) ensure .env is gitignored
    gi_path = project_root / ".gitignore"
    gi = gi_path.read_text(encoding="utf-8", errors="ignore") if gi_path.exists() else ""
    if ".env" not in [l.strip() for l in gi.splitlines()]:
        with open(gi_path, "a", encoding="utf-8") as fh:
            fh.write(("\n" if gi and not gi.endswith("\n") else "") + ".env\n")
        changes.append("Added .env to .gitignore")

    return FixResult(
        finding_id=finding.id,
        success=True,
        changes=changes,
        manual_actions=preview.manual_actions,
    )
