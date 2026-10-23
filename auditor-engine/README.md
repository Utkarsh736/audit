# Auditor — Agentic Security Auditor

An agentic security auditor for code projects and LLM applications. It scans
your codebase for vulnerabilities, explains every issue in plain English, and
gives you step-by-step, OWASP/CWE-aligned remediation — with an optional LLM
enrichment layer for deeper, code-specific guidance.

```
audit scan ./my-project            # scan + colorized terminal report
audit explain SECRET-001           # full remediation guide for one finding
audit fix ./my-project --finding SECRET-001   # apply safe auto-fixes
```

## Design philosophy (why it is built this way)

1. **Deterministic detection, optional AI explanation.** The scanners
   (regex + AST) decide what is vulnerable. The LLM never does. This makes
   results reproducible, fast (milliseconds, not minutes), cheap, and safe
   for CI — a security tool that hallucinates findings is worse than none.
2. **The engine is a Python package; the CLI is a thin wrapper.** The same
   `run_audit()` API powers the CLI and the web dashboard, and can later power
   a GitHub Action, a pre-commit hook, or a VS Code extension.
3. **Zero external tool dependencies.** No need to install Semgrep/Gitleaks —
   the built-in scanners work out of the box on Python, JavaScript/TypeScript,
   config files, Dockerfiles, and templates.
4. **A security tool must not leak secrets.** Findings mask secret values
   (`gsk_abc...wxyz`) everywhere: terminal, JSON, Markdown, and LLM prompts.
5. **Curated knowledge base over RAG for v1.** A JSON KB (40 rules) with
   CWE/OWASP references and copy-pasteable fixes is deterministic and offline.
   A RAG layer can be added later for org-specific policy.

## Install

With [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv venv && uv pip install -e .    # local .venv with the `audit` command
uv run audit scan ./my-project    # run via uv, or .venv/bin/audit directly
uv tool install --editable .      # alternative: `audit` on PATH, own isolated env
```

With plain pip:

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e .        # provides the `audit` command
```

Requires Python 3.10+ with `typer`, `rich`, `pydantic` (the only dependencies).

## Usage

```bash
# Scan a project (terminal report, colorized)
audit scan ./my-chatbot-app

# Only specific checks
audit scan ./my-app --checks secrets,prompt-injection,data-handling

# JSON output for CI/CD, saved to a file
audit scan ./my-app --format json --output report.json

# Markdown report (for PR comments)
audit scan ./my-app --format markdown --output SECURITY.md

# Lowest severity to report / what fails the build
audit scan ./my-app --min-severity medium --fail-on critical

# Skip vendored/test paths
audit scan ./my-app --exclude "tests/*,fixtures/*"

# Detailed remediation guide for one finding (uses the last scan's cache)
audit explain PROMPT-001
audit explain SECRET-001 --project ./my-chatbot-app

# Apply safe, deterministic fixes (secrets -> env vars), with preview
audit fix ./my-app --finding SECRET-001          # asks for confirmation
audit fix ./my-app --finding SECRET-001 --yes    # no prompt
audit fix ./my-app --finding SECRET-001 --dry-run

# Engine info + rule catalog
audit info
audit info --format json
```

**Exit codes** (CI/CD ready): `0` = clean (or below threshold), `1` = findings
at/above `--fail-on`, `2` = usage/engine error.

## The 7 check categories (40 rules)

| Check | Catches | Example rules |
| --- | --- | --- |
| `secrets` | Hardcoded API keys (Groq/OpenAI/Anthropic/AWS/GitHub/Slack/Google/HF), JWTs, private keys, generic credentials | `SECRET-001` |
| `prompt-injection` | Raw user input interpolated into LLM prompts (f-strings, concat, JS template literals, LangChain templates) — OWASP LLM01 | `PROMPT-001` |
| `data-handling` | PII in logs/console, PII sent to LLMs without redaction — OWASP LLM02 | `DATA-001` |
| `auth` | FastAPI/Flask/Express endpoints without auth guards; RAG retrieval without per-user ACLs | `AUTH-001` |
| `insecure-output` | `dangerouslySetInnerHTML`, `innerHTML =`, unsanitized markdown, `render_template_string`, Jinja `\|safe` — OWASP LLM05/XSS | `OUTPUT-001` |
| `dangerous-code` | `eval`, `pickle.loads`, `shell=True`, unsafe `yaml.load`, `verify=False`, insecure randomness, MD5/SHA1, `trust_remote_code` | `CODE-001` |
| `configuration` | Committed `.env`, missing `.gitignore`, wildcard CORS, `debug=True` | `CONFIG-001` |

Every finding is a structured object: id, severity, category, file:line,
masked evidence, why-it-matters, impact, quick fix, step-by-step remediation,
before/after code, verification step, CWE/OWASP references, confidence,
auto-fixability.

## Optional LLM enrichment

The tool is fully functional offline. To add AI-generated, code-specific
remediation depth on top of the knowledge base, point it at any
OpenAI-compatible provider:

```bash
export AUDITOR_LLM_PROVIDER=groq        # or openai | openrouter | ollama | custom
export AUDITOR_LLM_API_KEY=gsk_...      # Groq has a free tier
export AUDITOR_LLM_MODEL=llama-3.3-70b-versatile   # optional
# local & offline: AUDITOR_LLM_PROVIDER=ollama AUDITOR_LLM_BASE_URL=http://localhost:11434/v1

audit scan ./my-app --llm auto    # auto = enrich only if a key is present
```

Only critical/high findings are enriched (max 10 by default), secrets are
masked before they reach the model, and any provider error falls back
silently to the knowledge base.

## Architecture

```
auditor-engine/
├── auditor/
│   ├── cli.py                  # Typer CLI: scan / explain / fix / info
│   ├── models.py               # pydantic Finding / AuditReport models
│   ├── engine/
│   │   ├── orchestrator.py     # run_audit() pipeline + history/cache
│   │   ├── discovery.py        # file walking, language detection, excludes
│   │   └── dedupe.py           # dedupe, severity ranking, stable IDs
│   ├── scanners/               # 7 deterministic scanners (regex + AST)
│   ├── knowledge/rules.json    # 40 curated rules with CWE/OWASP remediation
│   ├── llm/                    # optional OpenAI-compatible enrichment
│   ├── fixer/                  # safe auto-fixes (secret -> env var)
│   └── reporter/               # terminal (rich) / JSON / markdown renderers
└── pyproject.toml
```

Pipeline: discover → scan (parallel) → dedupe → rank → enrich (KB → optional
LLM) → report. Reports are cached in `~/.auditor/` (shared by CLI and
dashboard history).

## Extending

- **New rules**: add a pattern to a scanner + an entry in
  `auditor/knowledge/rules.json` (title, severity, CWE, OWASP, remediation
  steps, references).
- **New scanner**: subclass `BaseScanner`, declare `languages`, yield
  `Finding`s, register it in `scanners/__init__.py`.
- **Integrate external tools** (semgrep, gitleaks, bandit): wrap their JSON
  output as a scanner; they become another `tool_source` in the merged report.
- **GitHub Action / pre-commit**: call `auditor run_audit()` or shell out to
  `audit scan --format json --fail-on high` and use the exit code.

## Roadmap ideas

Dynamic/red-team probing of running apps, RAG over org-specific security
policy, per-rule severity overrides via config file, SARIF output for GitHub
code scanning.

## Try it on the demo

`demo-apps/vulnerable-chatbot` is an intentionally vulnerable LLM chatbot
(21 findings across all 7 categories):

```bash
audit scan ../demo-apps/vulnerable-chatbot
```
