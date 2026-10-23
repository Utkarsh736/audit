"""Scanner registry."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..models import Finding
from .auth import AuthScanner
from .base import BaseScanner
from .config_scan import ConfigScanner
from .dangerous import DangerousCodeScanner
from .pii import DataHandlingScanner
from .prompt_injection import PromptInjectionScanner
from .output import InsecureOutputScanner
from .secrets import SecretsScanner

SCANNERS: dict[str, type[BaseScanner]] = {
    "secrets": SecretsScanner,
    "prompt-injection": PromptInjectionScanner,
    "data-handling": DataHandlingScanner,
    "auth": AuthScanner,
    "insecure-output": InsecureOutputScanner,
    "dangerous-code": DangerousCodeScanner,
    "configuration": ConfigScanner,
}


def get_scanners(checks: list[str]) -> list[BaseScanner]:
    """Instantiate the scanners selected via --checks (category names)."""
    wanted = {c.strip().lower() for c in checks if c.strip()}
    if not wanted or "all" in wanted:
        return [cls() for cls in SCANNERS.values()]
    unknown = wanted - set(SCANNERS) - {"all"}
    if unknown:
        raise ValueError(f"Unknown check(s): {', '.join(sorted(unknown))}. Valid: {', '.join(SCANNERS)}")
    return [SCANNERS[c]() for c in SCANNERS if c in wanted]


def scan_project(root: Path, scanners: list[BaseScanner], files: list[tuple[Path, str]]) -> Iterable[Finding]:
    """Run all scanners across discovered files. Returns raw findings."""
    import concurrent.futures as cf

    def _run_one(scanner: BaseScanner, path: Path, language: str) -> list[Finding]:
        try:
            return list(scanner.scan_file(path, language, root))
        except Exception:
            return []  # a scanner bug must never crash the whole audit

    jobs = [
        (scanner, path, language)
        for scanner in scanners
        for path, language in files
        if scanner.applies_to(language)
    ]
    findings: list[Finding] = []
    if len(jobs) > 64:
        with cf.ThreadPoolExecutor(max_workers=8) as ex:
            for result in ex.map(lambda j: _run_one(*j), jobs):
                findings.extend(result)
    else:
        for job in jobs:
            findings.extend(_run_one(*job))

    # cross-file checks
    for scanner in scanners:
        if hasattr(scanner, "scan_project"):
            try:
                findings.extend(scanner.scan_project(root))  # type: ignore[attr-defined]
            except Exception:
                pass
    return findings
