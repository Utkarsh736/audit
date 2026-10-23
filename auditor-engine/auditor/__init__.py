"""auditor - an agentic security auditor for code and LLM applications.

Public API (used by the CLI, and reusable from any wrapper):
    from auditor import run_audit, AuditOptions
"""
__version__ = "0.1.0"

from .engine.orchestrator import AuditOptions, run_audit  # noqa: F401

__all__ = ["run_audit", "AuditOptions", "__version__"]
