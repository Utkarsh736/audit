"""Data-handling scanner - PII in logs, console output, and LLM prompts."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import PII_NAMES, BaseScanner


class DataHandlingScanner(BaseScanner):
    name = "data-handling"
    category = "data-handling"
    languages = ("python", "javascript")

    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        rel = self.rel(path, root)

        if language == "python":
            yield from self._scan_python(content, rel)
        elif language == "javascript":
            yield from self._scan_javascript(content, rel)

    # ------------------------------------------------------------------ python
    def _scan_python(self, content: str, rel: str) -> Iterable[Finding]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            tree = None
        lines = content.splitlines()

        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                log_rule = self._log_rule(func)

                if log_rule and self._find_pii_in_args(node, lines):
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    yield self.make_finding(log_rule, Severity.MEDIUM, rel, node.lineno, snippet, confidence="medium")

                # LLM prompt with PII: complete(...)/client.chat.completions.create(...)
                func_name = ""
                if isinstance(func, ast.Attribute):
                    func_name = func.attr
                elif isinstance(func, ast.Name):
                    func_name = func.id
                if func_name and re.match(
                    r"^(create|generate|complete|invoke|call|chat|ask|send|predict|query|answer)$", func_name, re.I
                ):
                    if self._has_pii_fstring_arg(node):
                        snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                        yield self.make_finding(
                            "data.pii_to_llm", Severity.HIGH, rel, node.lineno, snippet, confidence="low"
                        )

    @staticmethod
    def _log_rule(func: ast.expr) -> str | None:
        """Map a call to a logging rule, or None if not a log call."""
        if isinstance(func, ast.Attribute):  # logger.info / logging.info
            if not re.match(r"^(info|debug|warning|warn|error|critical|exception)$", func.attr):
                return None
            callee = func.value
            if isinstance(callee, ast.Name) and re.match(
                r"^(log|logger|logging|audit|app|srv|root)$", callee.id, re.I
            ):
                return "data.pii_logging"
            return None
        if isinstance(func, ast.Name) and func.id == "print":
            return "data.pii_console"
        return None

    def _find_pii_in_args(self, call: ast.Call, lines: list[str]) -> list[str]:
        """Identifiers or f-string fields that look like PII inside log args."""
        hits: list[str] = []
        for arg in call.args:
            for n in ast.walk(arg):
                if isinstance(n, ast.Name) and PII_NAMES.search(n.id):
                    hits.append(n.id)
                if isinstance(n, ast.Attribute) and PII_NAMES.search(n.attr):
                    hits.append(n.attr)
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and PII_NAMES.search(n.value):
                    hits.append(n.value)
        return hits

    def _has_pii_fstring_arg(self, call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg in {"prompt", "input", "messages", "content", "user_prompt"}:
                for n in ast.walk(kw.value):
                    if isinstance(n, ast.Name) and PII_NAMES.search(n.id):
                        return True
                    if isinstance(n, ast.Attribute) and PII_NAMES.search(n.attr):
                        return True
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and PII_NAMES.search(n.value):
                        return True
        for arg in call.args:
            if isinstance(arg, ast.JoinedStr):
                for n in ast.walk(arg):
                    if isinstance(n, ast.Name) and PII_NAMES.search(n.id):
                        return True
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and PII_NAMES.search(n.value):
                        return True
        return False

    # -------------------------------------------------------------- javascript
    def _scan_javascript(self, content: str, rel: str) -> Iterable[Finding]:
        # console.log/warn/error/info with template literal or string + PII names
        pattern = re.compile(
            r"""(?ix)console\.(?:log|info|warn|error|debug)\s*\(
            (?P<body>(?:(?!\n)[\s\S])*)
            """
        )
        for m in pattern.finditer(content):
            body = m.group("body")
            if not PII_NAMES.search(body):
                continue
            # require something dynamic: interpolation, concat, or a variable argument
            if not re.search(r"(\$\{|\+|,\s*[A-Za-z_$][\w$.]*)", body):
                continue
            line_no = self.line_of(content, m.start())
            line_text = content.splitlines()[line_no - 1]
            if self.is_comment_line(line_text):
                continue
            yield self.make_finding(
                "data.pii_console",
                Severity.MEDIUM,
                rel,
                line_no,
                line_text.strip(),
                confidence="medium",
            )
