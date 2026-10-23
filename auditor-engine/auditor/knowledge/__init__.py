"""Security knowledge base - curated OWASP/CWE-aligned remediation guidance.

The KB is a JSON file (`rules.json`) keyed by rule ID. This is deterministic,
offline, and always-correct - a deliberately simpler alternative to a RAG
pipeline for a fixed rule set. A RAG layer can be added later for
organization-specific policies.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from ..models import Finding, Remediation

RULES_PATH = Path(__file__).parent / "rules.json"


@lru_cache(maxsize=1)
def _load_rules() -> dict[str, dict[str, Any]]:
    with open(RULES_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def get_rule(rule_id: str) -> Optional[dict[str, Any]]:
    return _load_rules().get(rule_id)


def all_rules() -> dict[str, dict[str, Any]]:
    return _load_rules()


def enrich(finding: Finding) -> Finding:
    """Fill description/impact/fix guidance on a finding from the KB."""
    rule = get_rule(finding.rule_id)
    if not rule:
        return finding
    finding.title = finding.title if finding.title and finding.title != finding.rule_id else rule.get("title", finding.title)
    if not finding.description:
        finding.description = rule.get("description", "")
    if not finding.impact:
        finding.impact = rule.get("impact", "")
    if not finding.quick_fix:
        finding.quick_fix = rule.get("quick_fix", "")
    finding.cwe = rule.get("cwe")
    finding.owasp = rule.get("owasp", [])
    finding.auto_fixable = finding.auto_fixable or bool(rule.get("auto_fix"))
    rem = rule.get("remediation")
    if rem:
        finding.remediation = Remediation(**rem)
    refs: list[str] = list(rule.get("references", []))
    if finding.cwe and f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[-1]}.html" not in refs:
        refs.insert(0, f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[-1]}.html")
    finding.references = refs
    return finding


def rule_catalog() -> list[dict[str, Any]]:
    """Flat catalog for `audit info` and the dashboard."""
    out = []
    for rule_id, rule in sorted(all_rules().items()):
        out.append(
            {
                "rule_id": rule_id,
                "title": rule.get("title", rule_id),
                "severity": rule.get("severity", "info"),
                "category": rule.get("category", ""),
                "cwe": rule.get("cwe"),
                "owasp": rule.get("owasp", []),
                "owasp_llm": rule.get("owasp_llm", []),
                "auto_fix": bool(rule.get("auto_fix")),
            }
        )
    return out
