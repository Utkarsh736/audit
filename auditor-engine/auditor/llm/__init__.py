"""Optional LLM enrichment layer.

The LLM NEVER decides what is vulnerable (deterministic scanners do that).
It only generates deeper, code-specific remediation guidance for the most
severe findings - and the tool is fully functional without it.

Configuration (all optional):
    AUDITOR_LLM_PROVIDER  groq | openai | openrouter | ollama | custom  (default groq)
    AUDITOR_LLM_API_KEY   provider API key
    AUDITOR_LLM_MODEL     model name (default llama-3.3-70b-versatile for groq)
    AUDITOR_LLM_BASE_URL  override the provider base URL

Any OpenAI-compatible endpoint works, including a local Ollama
(http://localhost:11434/v1) for fully offline usage.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from ..models import AuditReport, Finding

PROVIDER_DEFAULTS = {
    "groq": {"base_url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile"},
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "model": "meta-llama/llama-3.3-70b-instruct:free"},
    "ollama": {"base_url": "http://localhost:11434/v1", "model": "llama3.3"},
}

PROMPT_TEMPLATE = """You are a senior application security engineer. A deterministic scanner found this vulnerability:

Finding: {id} - {title} (severity: {severity})
Rule: {rule_id} (CWE: {cwe})
File: {file}:{line}
Evidence (secret values are masked):
{evidence}

Knowledge-base guidance:
{kb}

Produce a concise remediation guide for THIS finding:
1. Why this is a problem (2-3 sentences, grounded in the shown code - no invention)
2. Step-by-step fix (concrete, copy-pasteable commands/code)
3. Before/after code snippet for this exact line
4. How to verify the fix

Rules:
- Be specific to the code shown. Do not give generic advice.
- Never reveal or reconstruct the masked secret.
- Keep it under 250 words. Markdown format."""


class LLMConfig:
    def __init__(self) -> None:
        self.provider = os.environ.get("AUDITOR_LLM_PROVIDER", "groq").lower()
        self.api_key = os.environ.get("AUDITOR_LLM_API_KEY", os.environ.get("GROQ_API_KEY", ""))
        self.base_url = os.environ.get("AUDITOR_LLM_BASE_URL", "")
        self.model = os.environ.get("AUDITOR_LLM_MODEL", "")
        defaults = PROVIDER_DEFAULTS.get(self.provider, {})
        self.base_url = self.base_url or defaults.get("base_url", "")
        self.model = self.model or defaults.get("model", "")
        if self.provider == "ollama":
            self.api_key = self.api_key or "ollama"  # ollama ignores the key

    @property
    def available(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)


def _chat(config: LLMConfig, prompt: str, timeout: int = 45) -> str | None:
    payload = json.dumps(
        {
            "model": config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 700,
        }
    ).encode()
    req = urllib.request.Request(
        f"{config.base_url.rstrip('/')}/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, KeyError, IndexError, TimeoutError, json.JSONDecodeError):
        return None


def _code_context(report: AuditReport, finding: Finding, max_lines: int = 24) -> str:
    """Surrounding source lines (secrets already masked in evidence)."""
    from pathlib import Path as _Path

    try:
        path = _Path(report.project_path) / finding.file
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return finding.evidence
    start = max(0, finding.line - 1 - 8)
    end = min(len(lines), finding.line - 1 + max_lines - 8)
    excerpt = "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))
    # mask anything that looks like a credential in the excerpt
    return re.sub(r"(gsk_|sk-|AKIA|ghp_|xox[baprs]-|hf_|AIza)[A-Za-z0-9_\-]{8,}", r"\1***MASKED***", excerpt)


def enrich_report(report: AuditReport, options) -> None:
    """Attach LLM guidance to top findings. Fails soft: without a key or on
    any error the report simply keeps its knowledge-base remediation."""
    from ..knowledge import get_rule

    config = LLMConfig()
    if options.use_llm == "auto" and not (config.api_key and config.base_url):
        report.metadata.llm_note = "LLM enrichment skipped (no AUDITOR_LLM_API_KEY set) - knowledge-base guidance only."
        return
    if not config.available:
        if options.use_llm == "on":
            report.metadata.llm_note = "LLM enrichment unavailable: incomplete provider config."
        return

    candidates = [
        f for f in report.findings
        if f.severity.value in ("critical", "high") and f.llm_detail is None
    ][: options.max_llm_findings]
    if not candidates:
        report.metadata.llm_note = "No critical/high findings to enrich."
        return

    ok = 0
    for finding in candidates:
        rule = get_rule(finding.rule_id) or {}
        kb = json.dumps(
            {
                "description": rule.get("description", ""),
                "impact": rule.get("impact", ""),
                "steps": (rule.get("remediation") or {}).get("steps", []),
            },
            indent=1,
        )
        prompt = PROMPT_TEMPLATE.format(
            id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            rule_id=finding.rule_id,
            cwe=finding.cwe or "-",
            file=finding.file,
            line=finding.line,
            evidence=finding.evidence,
            kb=kb[:1200],
        )
        answer = _chat(config, prompt)
        if answer:
            finding.llm_detail = answer.strip()
            ok += 1
    if ok:
        report.metadata.llm_enriched = True
        report.metadata.llm_note = f"LLM enrichment: {ok}/{len(candidates)} findings (provider: {config.provider}, model: {config.model})."
    else:
        report.metadata.llm_note = "LLM enrichment attempted but provider unreachable - knowledge-base guidance only."
