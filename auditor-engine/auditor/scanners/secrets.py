"""Secrets scanner - detects hardcoded credentials across all text files."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import PLACEHOLDER_VALUES, BaseScanner, mask_secret

# (rule_id, regex, severity, confidence, env_var_override)
SECRET_PATTERNS: list[tuple[str, str, str, str, str | None]] = [
    ("secret.groq_key", r"gsk_[A-Za-z0-9]{20,}", "critical", "high", "GROQ_API_KEY"),
    ("secret.anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{20,}", "critical", "high", "ANTHROPIC_API_KEY"),
    ("secret.openai_key", r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{24,}", "critical", "high", "OPENAI_API_KEY"),
    ("secret.aws_key", r"\bAKIA[0-9A-Z]{16}\b", "critical", "high", "AWS_ACCESS_KEY_ID"),
    ("secret.github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|github_pat_[A-Za-z0-9_]{22,}", "critical", "high", "GITHUB_TOKEN"),
    ("secret.slack_token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "critical", "high", "SLACK_BOT_TOKEN"),
    ("secret.google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}", "critical", "high", "GOOGLE_API_KEY"),
    ("secret.huggingface_token", r"\bhf_[A-Za-z0-9]{34}\b", "critical", "high", "HF_TOKEN"),
    ("secret.jwt_token", r"\beyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\b", "high", "high", None),
    ("secret.private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----", "critical", "high", None),
]

# Generic credential assignment: api_key = "literal", password: 'literal', ...
GENERIC_CREDENTIAL = re.compile(
    r"""(?ix)\b
    (?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key|access[_\-]?key|
       secret|token|passwd|password|auth[_\-]?token|bearer|private[_\-]?key)
    \s*[:=]\s*
    (["'`])(?P<val>[^"'`\s]{12,})\1
    """
)

# Environments where a literal secret is acceptable (loaded from env manager)
ENV_ACCESS = re.compile(r"os\.environ(?:\.get)?\[|getenv\s*\(|process\.env\.", re.IGNORECASE)


class SecretsScanner(BaseScanner):
    name = "secrets"
    category = "secrets"
    languages = ("python", "javascript", "config", "text", "dockerfile", "yaml")

    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        # Whole-file exemptions: .env files are the CORRECT place for secrets
        # (the committed-.env risk is handled by the configuration scanner),
        # and example/template files are documentation.
        name_lower = path.name.lower()
        if name_lower.startswith(".env") or name_lower in {
            ".env.example", ".env.sample", ".env.template", ".env.dist"
        }:
            return

        rel = self.rel(path, root)
        seen_spans: set[tuple[str, int]] = set()
        flagged_lines: set[int] = set()

        for rule_id, pattern, sev, conf, env_var in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                line_no = self.line_of(content, m.start())
                line_text = content.splitlines()[line_no - 1] if content.count("\n") >= line_no - 1 else ""
                if self.is_comment_line(line_text):
                    continue
                key = (rule_id, line_no)
                if key in seen_spans:
                    continue
                seen_spans.add(key)
                flagged_lines.add(line_no)
                masked_line = line_text.replace(m.group(0), mask_secret(m.group(0)))
                finding = self.make_finding(
                    rule_id,
                    Severity(sev),
                    rel,
                    line_no,
                    masked_line.strip(),
                    confidence=conf,
                )
                if env_var:
                    finding.auto_fixable = True
                yield finding

        # Generic credential assignments (lower confidence)
        for m in GENERIC_CREDENTIAL.finditer(content):
            val = m.group("val")
            if PLACEHOLDER_VALUES.match(val):
                continue
            if re.match(r"^[A-Za-z0-9_.\-]+$", val) and len(val) < 16 and not re.search(r"\d", val):
                # short alphabetic words are usually identifiers, not secrets
                continue
            line_no = self.line_of(content, m.start())
            line_text = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
            if self.is_comment_line(line_text):
                continue
            # skip lines where the value comes from an env access construct
            start = content.rfind("\n", 0, m.start()) + 1
            if ENV_ACCESS.search(content[start:m.end()]):
                continue
            key = ("secret.generic_credential", line_no)
            if key in seen_spans or line_no in flagged_lines:
                continue
            seen_spans.add(key)
            masked_line = line_text.replace(val, mask_secret(val))
            yield self.make_finding(
                "secret.generic_credential",
                Severity.HIGH,
                rel,
                line_no,
                masked_line.strip(),
                confidence="medium",
            )
