"""Prompt-injection scanner (OWASP LLM01).

Python detection is AST-based: we find f-strings / concatenations that mix
instruction-like text with untrusted user-input identifiers. JS/TS detection
is regex-based on template literals.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import USER_INPUT_NAMES, BaseScanner

PROMPT_KEYWORDS = re.compile(
    r"(system|prompt|instruction|you are|act as|assistant|respond|answer|"
    r"translate|summar|chat completion|completion|role|context|llm|gpt|"
    r"claude|gemini|ai assistant)",
    re.IGNORECASE,
)

# langchain PromptTemplate(input_variables=[...], template="...{var}...")
LANGCHAIN_TEMPLATE = re.compile(
    r"(?:PromptTemplate|ChatPromptTemplate)\s*\(\s*(?:input_variables\s*=\s*)?\[([^\]]*)\]"
    r"[\s\S]{0,200}?template\s*=\s*([\"'])((?:(?!\2).)*)\2",
    re.IGNORECASE,
)

JS_TEMPLATE_PROMPT = re.compile(
    r"""(?ix)(["'`])(?:(?!\1)[\s\S]){0,120}?
    (?:system|prompt|instruction|you\s+are|assistant|answer|translate|summar)[^"'`\n]{0,120}?
    \$\{\s*([A-Za-z_$][\w$]*)\s*\}"""
)


class PromptInjectionScanner(BaseScanner):
    name = "prompt-injection"
    category = "prompt-injection"
    languages = ("python", "javascript")

    # ------------------------------------------------------------- python (AST)
    def _scan_python(self, tree: ast.AST, source: str, rel: str) -> Iterable[Finding]:
        lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                literal_text = "".join(
                    v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
                unsafe = [e for e in self._interpolated_exprs(node) if self._is_untrusted_name(e)]
                if unsafe and (PROMPT_KEYWORDS.search(literal_text) or self._assigned_to_prompt(node)):
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    yield self.make_finding(
                        "prompt.fstring_interpolation",
                        Severity.HIGH,
                        rel,
                        node.lineno,
                        snippet,
                        confidence="medium",
                        end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    )

            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                parts = self._flatten_concat(node)
                literals = " ".join(p for p in parts if isinstance(p, str))
                names = [p for p in parts if p is not None and not isinstance(p, str)]
                if (
                    PROMPT_KEYWORDS.search(literals)
                    and any(USER_INPUT_NAMES.match(n) for n in names)
                ):
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    yield self.make_finding(
                        "prompt.concat_interpolation",
                        Severity.HIGH,
                        rel,
                        node.lineno,
                        snippet,
                        confidence="medium",
                    )

    @staticmethod
    def _interpolated_exprs(node: ast.JoinedStr) -> list[ast.AST]:
        """Expressions interpolated into an f-string (PEP 701 and older)."""
        exprs: list[ast.AST] = []
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                exprs.append(v.value)
            elif isinstance(v, ast.Name):
                exprs.append(v)
        return exprs

    @staticmethod
    def _is_untrusted_name(expr: ast.AST) -> bool:
        """True if the expression is a user-input-ish identifier (or attr)."""
        if isinstance(expr, ast.Name):
            return bool(USER_INPUT_NAMES.match(expr.id))
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            combined = f"{expr.value.id}.{expr.attr}"
            if USER_INPUT_NAMES.match(expr.value.id) or USER_INPUT_NAMES.match(expr.attr):
                return True
            return bool(USER_INPUT_NAMES.match(combined))
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
            return bool(USER_INPUT_NAMES.match(expr.func.id))  # sanitize(x) style
        return False

    def _assigned_to_prompt(self, node: ast.AST) -> bool:
        """True if the f-string result is assigned to a prompt-ish variable."""
        for parent in getattr(node, "_parents", []):  # populated below
            if isinstance(parent, ast.Assign) and any(
                isinstance(t, ast.Name) and re.match(r"(?i).*(prompt|instruction|template|message|query)", t.id)
                for t in parent.targets
            ):
                return True
        return False

    def _flatten_concat(self, node: ast.AST) -> list:
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._flatten_concat(node.left) + self._flatten_concat(node.right)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            return [node.id]
        return [None]

    # --------------------------------------------------------------- javascript
    def _scan_javascript(self, content: str, rel: str) -> Iterable[Finding]:
        for m in JS_TEMPLATE_PROMPT.finditer(content):
            var = m.group(3)
            if not USER_INPUT_NAMES.match(var):
                continue
            line_no = self.line_of(content, m.start())
            line_text = content.splitlines()[line_no - 1]
            if self.is_comment_line(line_text):
                continue
            yield self.make_finding(
                "prompt.js_template_literal",
                Severity.HIGH,
                rel,
                line_no,
                line_text.strip(),
                confidence="medium",
            )

    def _scan_langchain(self, content: str, rel: str) -> Iterable[Finding]:
        for m in LANGCHAIN_TEMPLATE.finditer(content):
            variables = re.findall(r"[\"']([\w]+)[\"']", m.group(1))
            template = m.group(3)
            user_vars = [v for v in variables if USER_INPUT_NAMES.match(v)]
            if not user_vars:
                # template itself interpolates user-ish placeholders
                user_vars = [v for v in re.findall(r"\{(\w+)\}", template) if USER_INPUT_NAMES.match(v)]
            if not user_vars:
                continue
            line_no = self.line_of(content, m.start())
            snippet = content.splitlines()[line_no - 1].strip()
            yield self.make_finding(
                "prompt.langchain_raw_template",
                Severity.MEDIUM,
                rel,
                line_no,
                snippet,
                confidence="medium",
            )

    # --------------------------------------------------------------------- main
    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        rel = self.rel(path, root)

        if language == "python":
            try:
                tree = ast.parse(content)
            except SyntaxError:
                tree = None
            if tree is not None:
                # record parents for context checks
                for parent in ast.walk(tree):
                    for child in ast.iter_child_nodes(parent):
                        setattr(child, "_parents", [parent])
                yield from self._scan_python(tree, content, rel)
            yield from self._scan_langchain(content, rel)
        elif language == "javascript":
            yield from self._scan_javascript(content, rel)
