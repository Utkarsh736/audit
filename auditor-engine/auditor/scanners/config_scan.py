"""Configuration scanner - cross-file project hygiene checks.

Detects: committed .env, missing .gitignore, wildcard CORS, debug=True.
Also covers RAG retrieval without per-user filters (auth.rag_no_access_control).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import BaseScanner

CORS_WILDCARD = re.compile(
    r"""(?ix)(?:allow[_\-]?origins|allowed[_\-]?origins|origin|access[_\-]?control[_\-]?allow[_\-]?origin)\s*
    [=:]\s*(?:\[[^\]]*\*[^\]]*\]|["'][^"']*\*[^"']*["'])"""
)
DEBUG_TRUE = re.compile(r"(?i)debug\s*[=:]\s*(?:True|true|['\"]true['\"]|1)")
SIMILARITY_SEARCH = re.compile(r"(?ix)\.(?:similarity_search|as_retriever|max_marginal_relevance_search)\s*\((?P<args>[^\n]*)")


class ConfigScanner(BaseScanner):
    name = "configuration"
    category = "configuration"
    # config language = .env, .gitignore, yaml, toml, json, dockerfile, ini...
    languages = ("python", "javascript", "config", "yaml", "dockerfile", "text")

    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        rel = self.rel(path, root)
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            if self.is_comment_line(line):
                continue
            if CORS_WILDCARD.search(line):
                yield self.make_finding(
                    "config.cors_wildcard", Severity.MEDIUM, rel, i, line.strip(), confidence="high"
                )
            if DEBUG_TRUE.search(line) and not re.search(r"(?i)test|spec|example", rel):
                # only flag app-run style lines, not random debug flags
                if re.search(r"(?i)(app\.run|uvicorn|flask|run\(|add_middleware|settings|config)", line):
                    yield self.make_finding(
                        "config.debug_true", Severity.LOW, rel, i, line.strip(), confidence="medium"
                    )
            # RAG retrieval without ACL filter (python)
            if language == "python":
                m = SIMILARITY_SEARCH.search(line)
                if m and "filter" not in (m.group("args") or "") and "k=" in m.group("args"):
                    f = self.make_finding(
                        "auth.rag_no_access_control",
                        Severity.HIGH,
                        rel,
                        i,
                        line.strip(),
                        confidence="medium",
                    )
                    f.category = "auth"  # categorized under access control
                    yield f

    def scan_project(self, root: Path) -> Iterable[Finding]:
        """Cross-file checks executed once per project."""
        # --- .env committed? ---
        env_candidates = [".env", ".env.local", ".env.production", ".env.development"]
        for env_name in env_candidates:
            env_file = root / env_name
            if not env_file.exists() or self._is_gitignored(root, env_name):
                continue
            first_line = ""
            try:
                content = env_file.read_text(encoding="utf-8", errors="ignore")
                non_comment = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
                if non_comment:
                    key = non_comment[0].split("=")[0]
                    first_line = f"{key}=***redacted***"
            except OSError:
                pass
            yield self.make_finding(
                "config.env_committed",
                Severity.CRITICAL,
                env_name,
                1,
                first_line or f"({env_name} file exists but is not ignored by .gitignore)",
                confidence="high",
            )

        # --- .gitignore missing ---
        if not (root / ".gitignore").exists() and (root / ".env").exists():
            yield self.make_finding(
                "config.gitignore_missing",
                Severity.LOW,
                ".gitignore",
                1,
                "(no .gitignore file in project root)",
                confidence="high",
            )

    @staticmethod
    def _is_gitignored(root: Path, rel_name: str) -> bool:
        gi = root / ".gitignore"
        if not gi.exists():
            return False
        try:
            content = gi.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        for raw in content.splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            entry = entry.lstrip("/")
            if entry in {rel_name, ".env", ".env.*", ".env*"} or rel_name.startswith(entry.rstrip("*")):
                return True
        return False
