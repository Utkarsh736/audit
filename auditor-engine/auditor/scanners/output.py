"""Insecure-output scanner - OWASP LLM05 (improper output handling / XSS)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import BaseScanner

LITERAL_HTML = re.compile(r"^[\"'][^\"'<>]*[\"']$")

DANGEROUS_HTML = re.compile(
    r"""(?ix)
    (?P<danger>dangerouslySetInnerHTML) |
    \.innerHTML\s*= |
    (?:marked|markdown|md)\.?\s*(?:parse|render|to_html|toHtml)\s*\( |
    render_template_string\s*\( |
    \|\s*safe\s*[}\n] |
    document\.write\s*\(
    """
)


class InsecureOutputScanner(BaseScanner):
    name = "insecure-output"
    category = "insecure-output"
    languages = ("python", "javascript", "template")

    def scan_file(self, path: Path, language: str, root: Path) -> Iterable[Finding]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        rel = self.rel(path, root)
        lines = content.splitlines()

        for m in DANGEROUS_HTML.finditer(content):
            line_no = self.line_of(content, m.start())
            line_text = lines[line_no - 1] if line_no <= len(lines) else ""
            if self.is_comment_line(line_text):
                continue
            token = m.group("danger") or m.group(0).split("(")[0].split("=")[0].strip().strip(".")

            if language == "python":
                if "render_template_string" in token or "render_template_string" in line_text:
                    rule = "output.render_template_string"
                else:
                    continue
                sev, conf = Severity.HIGH, "medium"
            elif language == "template":
                if "| safe" in line_text or "|safe" in line_text:
                    rule = "output.jinja_safe_filter"
                else:
                    continue
                sev, conf = Severity.HIGH, "high"
            else:  # javascript / typescript
                if token == "dangerouslySetInnerHTML":
                    rule = "output.dangerously_set_inner_html"
                    # raw literal HTML is safe-ish; flag only dynamic-looking usage
                    if re.search(r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(\"|')[^\"']*(\"|')", line_text):
                        continue
                elif "innerHTML" in token:
                    rule = "output.inner_html_assignment"
                    if LITERAL_HTML.match(line_text.split("=", 1)[1].strip() if "=" in line_text else ""):
                        continue
                elif "document.write" in token or "document.write" in line_text:
                    rule = "output.inner_html_assignment"
                elif "marked" in token or "markdown" in token or "md" in token:
                    rule = "output.markdown_unsanitized"
                    if "sanitize" in line_text or "DOMPurify" in line_text:
                        continue
                else:
                    continue
                sev, conf = Severity.HIGH, "medium"

            yield self.make_finding(rule, sev, rel, line_no, line_text.strip(), confidence=conf)
