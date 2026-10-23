"""Scanner framework.

Each scanner is a deterministic detector (regex + AST). The LLM never decides
what is vulnerable - that is the scanners' job. This keeps results reproducible,
fast, and safe to run in CI.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity

# Identifier names that typically hold untrusted user input.
USER_INPUT_NAMES = re.compile(
    r"^(user[_\-]?input|user[_\-]?message|user[_\-]?msg|user[_\-]?query|"
    r"user[_\-]?text|user[_\-]?prompt|user[_\-]?question|user[_\-]?content|"
    r"chat[_\-]?input|input[_\-]?text|message|messages|msg|query|question|"
    r"prompt|user_input_raw|conversation|transcript|req[_\-]?query|"
    r"req[_\-]?body|request[_\-]?text|input_str|text_input|human_input)$",
    re.IGNORECASE,
)

# Identifier names that look like PII fields.
PII_NAMES = re.compile(
    r"(email|mail|phone|mobile|tel\b|ssn|social_security|passport|dob\b|"
    r"date[_\-]?of[_\-]?birth|first[_\-]?name|last[_\-]?name|full[_\-]?name|"
    r"home[_\-]?address|street[_\-]?address|postal|zip[_\-]?code|iban|"
    r"credit[_\-]?card|card[_\-]?number|avatar|ssn\b)",
    re.IGNORECASE,
)

# Placeholder values that are not real secrets.
PLACEHOLDER_VALUES = re.compile(
    r"^(your[_\-]?(api[_\-]?)?key|your[_\-]?key|xxx+|x{3,}|<[^>]+>|\{[^}]*\}|"
    r"\$\{[^}]*\}|example.*|sample.*|test.*|dummy.*|placeholder.*|changeme|"
    r"change[_\-]me|replace[_\-]me|insert.*|paste.*|todo|fixme|not[_\-]?a[_\-]?real.*|"
    r"fake.*|redacted|secret_here|key_here|.*_here|abc+|123+|0+|none|null|true|false)$",
    re.IGNORECASE,
)

# Route paths considered intentionally public.
PUBLIC_PATH_HINTS = (
    "/health", "/healthz", "/ready", "/readiness", "/live", "/liveness",
    "/ping", "/status", "/metrics", "/version", "/info", "/docs",
    "/openapi.json", "/redoc", "/favicon", "/static", "/public", "/",
)


class BaseScanner:
    """Base class for all scanners.

    A scanner declares which languages it applies to and implements
    ``scan_file`` returning raw Finding objects. IDs and knowledge-base
    enrichment happen later, in the orchestrator.
    """

    name: str = "base"
    category: str = "unknown"

    #: language keys (from discovery) this scanner wants to see
    languages: tuple[str, ...] = ()

    def applies_to(self, language: str) -> bool:
        return language in self.languages

    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        """Yield findings for a single file. `path` is absolute; findings must
        store `file` relative to `root`."""
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def rel(path: Path, root: Path) -> str:
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(path)

    @staticmethod
    def line_of(content: str, index: int) -> int:
        return content.count("\n", 0, index) + 1

    @staticmethod
    def snippet(content: str, index: int, span: int = 0) -> str:
        """Return the source line(s) covering [index, index+span]."""
        start = content.rfind("\n", 0, index) + 1
        end = content.find("\n", index + max(span, 1))
        if end == -1:
            end = len(content)
        # include a small span of following lines for context if requested
        if span > 0:
            lines_end = end
            for _ in range(span):
                nxt = content.find("\n", lines_end + 1)
                lines_end = nxt if nxt != -1 else len(content)
            end = lines_end
        return content[start:end].strip()

    @staticmethod
    def is_comment_line(line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*")

    def make_finding(
        self,
        rule_id: str,
        severity: Severity,
        file: str,
        line: int,
        evidence: str,
        title: str = "",
        confidence: str = "medium",
        end_line: int = 0,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            severity=severity,
            category=self.category,
            title=title or rule_id,
            file=file,
            line=line,
            end_line=end_line or line,
            evidence=evidence,
            confidence=confidence,  # type: ignore[arg-type]
            tool_source=f"built-in:{self.name}",
        )


def mask_secret(value: str) -> str:
    """Mask a secret so reports never echo full credentials.

    A security tool leaking the secrets it found would itself be a
    vulnerability (CWE-532).
    """
    value = value.strip()
    if len(value) <= 10:
        return value[:2] + "***"
    return f"{value[:6]}...{value[-4:]}"
