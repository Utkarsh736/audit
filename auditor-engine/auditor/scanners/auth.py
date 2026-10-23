"""Auth scanner - detects API endpoints without authentication guards.

AST-based for FastAPI/Flask; regex-based for Express (JS).
Known-public paths (health checks, docs) are exempt.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from ..models import Finding, Severity
from .base import BaseScanner

AUTH_HINTS = re.compile(
    r"(?i)(auth|login|require|verify|jwt|token|session|permission|admin|"
    r"current_user|get_current|api_key|security|passport|role|rbac|guard)"
)
FASTAPI_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
FLASK_METHODS = {"route", "add_url_rule", "get", "post", "put", "delete", "patch"}
PUBLIC_PATH_RE = re.compile(
    r"^(?:/|/health\w*|/ready\w*|/live\w*|/ping|/status|/metrics|/version|/info|"
    r"/docs|/redoc|/openapi\.\w+|/favicon\.\w+|/static/[\s\S]*|/public/[\s\S]*)$",
    re.IGNORECASE,
)

# app.get('/path', handler) / router.post('/path', mw, handler)
EXPRESS_ROUTE = re.compile(
    r"""(?ix)\b(?:app|router|server|api)\s*\.\s*(get|post|put|delete|patch|all)\s*
    \(\s*(['"`])(?P<path>(?:(?!\2)[^\n])*)\2\s*,\s*(?P<rest>[^\n]*)"""
)


class AuthScanner(BaseScanner):
    name = "auth"
    category = "auth"
    languages = ("python", "javascript")

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
                return
            yield from self._scan_python(tree, content, rel)
        elif language == "javascript":
            yield from self._scan_javascript(content, rel)

    # ------------------------------------------------------------------ python
    def _scan_python(self, tree: ast.AST, content: str, rel: str) -> Iterable[Finding]:
        lines = content.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_info = self._route_decorator(node)
            if route_info is None:
                continue
            framework, path_str = route_info
            if PUBLIC_PATH_RE.match(path_str):
                continue

            if self._has_auth_guard(node):
                continue

            rule = "auth.fastapi_unauthenticated" if framework == "fastapi" else "auth.flask_unauthenticated"
            snippet = self._decorator_snippet(node, lines)
            yield self.make_finding(
                rule,
                Severity.HIGH if framework == "fastapi" else Severity.MEDIUM,
                rel,
                node.lineno,
                snippet,
                confidence="medium",
            )

    def _route_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, str] | None:
        """Return (framework, path) if the function has a route decorator."""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                method = dec.func.attr
                receiver = dec.func.value
                receiver_name = receiver.id if isinstance(receiver, ast.Name) else ""
                if isinstance(receiver, ast.Attribute):  # app.router.get(...)
                    receiver_name = receiver.attr
                path_str = ""
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    path_str = str(dec.args[0].value)
                if method in FASTAPI_METHODS and receiver_name in {"app", "router", "api", "blueprint", "bp", "webhook"}:
                    return "fastapi", path_str
                if method in FLASK_METHODS and receiver_name in {"app", "blueprint", "bp", "server"}:
                    return "flask", path_str
            elif isinstance(dec, ast.Attribute):  # @app.route without call? skip
                continue
        return None

    def _has_auth_guard(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        # 1) auth-looking decorator args: dependencies=[Depends(verify_user)], Depends(...)
        #    NOTE: plain string constants are route paths, never guards.
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call):
                for arg in list(dec.args) + [k.value for k in dec.keywords]:
                    if isinstance(arg, ast.Constant):
                        continue  # a path string like "/admin/x" is not an auth guard
                    if isinstance(arg, ast.Name) and AUTH_HINTS.match(arg.id):
                        return True
                    if isinstance(arg, ast.Attribute) and AUTH_HINTS.search(arg.attr or ""):
                        return True
                    if isinstance(arg, ast.Call):
                        dump = ast.dump(arg)
                        if "Depends" in dump or "Security" in dump or AUTH_HINTS.search(
                            getattr(arg.func, "id", getattr(arg.func, "attr", "") or "")
                        ):
                            return True
        # 2) function parameters: current_user: User = Depends(get_current_user)
        arg_str = ast.dump(node.args) if hasattr(node, "args") else ""
        if AUTH_HINTS.search(arg_str) and "Depends" in arg_str:
            return True
        # 3) auth decorators on the function itself (@login_required)
        for dec in node.decorator_list:
            name = dec.id if isinstance(dec, ast.Name) else (dec.func.id if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) else "")
            if name and AUTH_HINTS.match(name):
                return True
            if isinstance(dec, ast.Attribute) and AUTH_HINTS.match(dec.attr or ""):
                return True
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and AUTH_HINTS.match(dec.func.attr or ""):
                return True
        return False

    def _decorator_snippet(self, node: ast.FunctionDef, lines: list[str]) -> str:
        dec_line = node.lineno - len(node.decorator_list) - 1
        dec_line = max(0, dec_line)
        end = min(len(lines), node.lineno)
        return "\n".join(l.strip() for l in lines[dec_line:end])

    # -------------------------------------------------------------- javascript
    def _scan_javascript(self, content: str, rel: str) -> Iterable[Finding]:
        for m in EXPRESS_ROUTE.finditer(content):
            path_str = m.group("path")
            if not path_str.startswith("/"):
                continue
            if PUBLIC_PATH_RE.match(path_str):
                continue
            rest = m.group("rest")
            # handler chain must contain an auth-ish middleware before the final handler
            middlewares = [mw.strip() for mw in rest.split(",")]
            # ignore the final handler itself (usually an arrow/function)
            chain = ", ".join(middlewares[:-1])
            if AUTH_HINTS.search(chain) or AUTH_HINTS.search(middlewares[-1] or ""):
                continue
            line_no = self.line_of(content, m.start())
            line_text = content.splitlines()[line_no - 1]
            if self.is_comment_line(line_text):
                continue
            yield self.make_finding(
                "auth.express_unauthenticated",
                Severity.HIGH,
                rel,
                line_no,
                line_text.strip(),
                confidence="medium",
            )
