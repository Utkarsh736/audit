"""File discovery: walk the project, detect languages, apply exclusions."""
from __future__ import annotations

import fnmatch
from pathlib import Path

EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".next", ".nuxt", "dist", "build", "out", "target", "vendor", ".tox",
    ".eggs", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".auditor",
    "coverage", ".idea", ".vscode", ".turbo", ".cache", ".gradle", "db",
}

EXCLUDE_FILE_SUFFIXES = (".min.js", ".min.css", ".map", ".lock", ".pyc", ".so", ".png", ".jpg",
                         ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
                         ".pdf", ".zip", ".tar", ".gz", ".jar", ".wasm", ".bin")

EXCLUDE_FILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "uv.lock", "Cargo.lock", "composer.lock", "Gemfile.lock",
    "go.sum", ".DS_Store", "Thumbs.db",
}

MAX_FILE_SIZE = 1_500_000  # 1.5 MB

EXT_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".html": "template", ".jinja": "template", ".j2": "template", ".ejs": "template",
    ".hbs": "template", ".pug": "template",
    ".env": "config",
    ".yaml": "yaml", ".yml": "yaml",
    ".toml": "config", ".cfg": "config", ".ini": "config", ".conf": "config",
    ".json": "config", ".dockerfile": "dockerfile",
}

SPECIAL_NAMES = {
    ".gitignore": "config", ".dockerignore": "config",
    "Dockerfile": "dockerfile", "docker-compose.yml": "yaml", "docker-compose.yaml": "yaml",
    "requirements.txt": "config", "pyproject.toml": "config", "setup.py": "python",
    "package.json": "config", ".env.example": "config", ".env.local": "config",
    ".env.production": "config", ".env.development": "config",
}

# Text files that secrets scanner can still check
TEXT_SUFFIXES = (".txt", ".md", ".rst", ".sh", ".bash", ".sql", ".tf", ".env")


class DiscoveredFile:
    __slots__ = ("path", "language", "lines")

    def __init__(self, path: Path, language: str, lines: int):
        self.path = path
        self.language = language
        self.lines = lines


def detect_language(path: Path) -> str | None:
    name = path.name
    if name in SPECIAL_NAMES:
        return SPECIAL_NAMES[name]
    if name.startswith(".env"):
        return "config"
    ext = path.suffix.lower()
    if ext in EXT_LANGUAGE:
        return EXT_LANGUAGE[ext]
    if ext == ".dockerfile" or name.lower().endswith("dockerfile"):
        return "dockerfile"
    if ext in TEXT_SUFFIXES:
        return "text"
    return None


def _is_excluded(rel_posix: str, excludes: list[str]) -> bool:
    """True if the relative path matches any exclude pattern.

    Patterns match the full relative path, any tail of it, or the basename:
    'auditor/knowledge/rules.json', 'knowledge/rules.json', 'rules.json',
    'tests/*' all work.
    """
    for pat in excludes:
        if fnmatch.fnmatch(rel_posix, pat):
            return True
        # match any tail of the path: a/b/c matches pattern b/c
        if "/" in pat:
            if rel_posix.endswith("/" + pat) or rel_posix == pat:
                return True
        else:
            if fnmatch.fnmatch(rel_posix.rsplit("/", 1)[-1], pat):
                return True
            if fnmatch.fnmatch("/".join(rel_posix.rsplit("/", 2)[-2:]), f"*/{pat}"):
                return True
    return False


def discover_files(root: Path, excludes: list[str] | None = None) -> list[DiscoveredFile]:
    """Walk `root` and return scannable files with their language.

    `excludes` are glob patterns matched against the path relative to the
    project root (e.g. "tests/*", "docs/*.md", "knowledge/rules.json").
    """
    files: list[DiscoveredFile] = []
    root = root.resolve()
    excludes = [e.lstrip("/") for e in (excludes or [])]
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        # skip excluded dirs anywhere in the path
        parts = path.relative_to(root).parts
        if any(p in EXCLUDE_DIRS for p in parts[:-1]):
            continue
        if path.name in EXCLUDE_FILE_NAMES:
            continue
        if path.suffix.lower() in EXCLUDE_FILE_SUFFIXES:
            continue
        rel_posix = "/".join(parts)
        if _is_excluded(rel_posix, excludes):
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE or path.stat().st_size == 0:
                continue
        except OSError:
            continue
        language = detect_language(path)
        if language is None:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").count("\n") + 1
        except OSError:
            lines = 0
        files.append(DiscoveredFile(path, language, lines))
    return files


def count_languages(files: list[DiscoveredFile]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in files:
        counts[f.language] = counts.get(f.language, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
