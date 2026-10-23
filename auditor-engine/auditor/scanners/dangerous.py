"""Dangerous-code scanner - unsafe API usage (eval, pickle, shell, weak crypto...)."""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import BaseScanner

JS_DANGEROUS = [
    (r"\beval\s*\(", "code.eval", Severity.HIGH),
    (r"\bnew\s+Function\s*\(", "code.eval", Severity.HIGH),
    (r"\bchild_process\b[\s\S]{0,40}\bexec\s*\(|\bexec\s*\(\s*[\"'`][^\"'`]*\$\{|\bexecSync\s*\(\s*[\"'`][^\"'`]*\$\{", "code.child_process_exec", Severity.HIGH),
    (r"\bMath\.random\s*\(\s*\)", None, Severity.LOW),  # only flagged near security names
]


class DangerousCodeScanner(BaseScanner):
    name = "dangerous-code"
    category = "dangerous-code"
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
            return
        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
            if not name:
                continue
            receiver = ""
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                receiver = func.value.id
            full = f"{receiver}.{name}" if receiver else name
            line_no = node.lineno
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

            # eval / exec
            if name in {"eval", "exec"} and not receiver:
                yield self.make_finding("code.eval", Severity.HIGH, rel, line_no, snippet, confidence="high")
                continue
            # pickle.loads / pickle.load
            if full in {"pickle.loads", "pickle.load", "cPickle.loads", "shelve.open", "dill.loads"}:
                yield self.make_finding("code.pickle_loads", Severity.HIGH, rel, line_no, snippet, confidence="high")
                continue
            # subprocess with shell=True
            if full in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        yield self.make_finding("code.shell_true", Severity.MEDIUM, rel, line_no, snippet, confidence="high")
                continue
            # os.system
            if full == "os.system":
                yield self.make_finding("code.shell_true", Severity.MEDIUM, rel, line_no, snippet, confidence="high")
                continue
            # yaml.load without SafeLoader
            if full == "yaml.load":
                loader_ok = False
                for kw in node.keywords:
                    if kw.arg == "Loader" and "Safe" in ast.dump(kw.value):
                        loader_ok = True
                if not loader_ok and not any(kw.arg == "Loader" for kw in node.keywords):
                    yield self.make_finding("code.yaml_unsafe_load", Severity.HIGH, rel, line_no, snippet, confidence="high")
                continue
            # TLS verify=False
            if full in {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.request", "requests.head"}:
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        yield self.make_finding("code.verify_false", Severity.HIGH, rel, line_no, snippet, confidence="high")
                continue
            if name == "create" and receiver in {"httpx.Client", "httpx.AsyncClient"} or full in {"httpx.Client", "httpx.AsyncClient"}:
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        yield self.make_finding("code.verify_false", Severity.HIGH, rel, line_no, snippet, confidence="high")
                continue
            # weak hashing
            if full in {"hashlib.md5", "hashlib.sha1"}:
                yield self.make_finding("code.weak_hash", Severity.LOW, rel, line_no, snippet, confidence="medium")
                continue
            # insecure randomness in security-ish contexts
            if receiver == "random" and name in {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle"}:
                ctx = "\n".join(lines[max(0, line_no - 6):line_no])
                if re.search(r"(?i)(token|secret|password|otp|nonce|salt|session|api[_\-]?key|key\s*=)", ctx):
                    yield self.make_finding("code.insecure_random", Severity.MEDIUM, rel, line_no, snippet, confidence="medium")
                continue
            # trust_remote_code=True
            if name in {"from_pretrained", "from_name"} or full in {"AutoModel.from_pretrained", "AutoTokenizer.from_pretrained"}:
                for kw in node.keywords:
                    if kw.arg == "trust_remote_code" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        yield self.make_finding("code.trust_remote_code", Severity.MEDIUM, rel, line_no, snippet, confidence="high")
                continue

    # -------------------------------------------------------------- javascript
    def _scan_javascript(self, content: str, rel: str) -> Iterable[Finding]:
        lines = content.splitlines()
        for pattern, rule, sev in JS_DANGEROUS:
            for m in re.finditer(pattern, content):
                line_no = self.line_of(content, m.start())
                line_text = lines[line_no - 1] if line_no <= len(lines) else ""
                if self.is_comment_line(line_text):
                    continue
                if rule is None:
                    # Math.random - only near security-ish variable names
                    ctx = "\n".join(lines[max(0, line_no - 6):line_no])
                    if not re.search(r"(?i)(token|secret|password|otp|nonce|session|apikey|api_key)", ctx):
                        continue
                    rule = "code.insecure_random"
                yield self.make_finding(rule, sev, rel, line_no, line_text.strip(), confidence="medium")
