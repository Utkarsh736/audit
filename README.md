# Auditor — Agentic Security Auditor

Security auditing for code projects and LLM applications.

| Component | What it does |
|-----------|--------------|
| **Engine** (`auditor-engine/`) | Python package with **7 deterministic scanner categories** (~40 rules): secrets, prompt injection, PII, authentication, insecure output handling, dangerous code, and configuration. Includes a curated OWASP/CWE knowledge base, optional LLM enrichment (any OpenAI-compatible provider), and safe auto-fixes. |
| **CLI** (`audit`) | Thin wrapper: `audit scan`, `audit explain`, `audit fix`, `audit info`. CI-friendly exit codes and JSON output. |
| **Dashboard** (this Next.js app) | Web UI over the same CLI — scan local projects, browse findings with remediation detail, shared history at `~/.auditor/history`. |
| **Demo** (`demo-apps/vulnerable-chatbot`) | Intentionally vulnerable LLM chatbot with planted findings for trying the tool end-to-end. |

The tool is fully functional offline. The LLM layer only adds deeper, code-specific remediation text on top of the built-in knowledge base.

---

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or plain `pip`
- [bun](https://bun.sh) (or npm/pnpm) for the dashboard

---

## Quick start

### 1. Engine + CLI

```bash
cd auditor-engine
uv venv
uv pip install -e .

# Run a scan
uv run audit scan ../demo-apps/vulnerable-chatbot

# Or activate the venv and use `audit` directly
source .venv/bin/activate
audit scan ../demo-apps/vulnerable-chatbot --format table
```

Install the CLI globally (optional):

```bash
uv tool install --editable ./auditor-engine   # puts `audit` on PATH (~/.local/bin)
```

<details>
<summary>Plain pip instead of uv</summary>

```bash
cd auditor-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

</details>

### 2. Dashboard

```bash
# From repo root
bun install   # or: npm install

# Point the dashboard at the engine venv (recommended)
export AUDITOR_PYTHON="$(pwd)/auditor-engine/.venv/bin/python"

bun run dev   # http://localhost:3000
```

Production:

```bash
bun run build && bun run start
```

On first use: enter a project path (or click **Use demo app**), then **Scan project**. Explore findings, filters, remediation steps, and the History tab.

The dashboard tries `AUDITOR_PYTHON` first, then `python3` / `python`. Setting `AUDITOR_PYTHON` to the uv venv ensures it uses the interpreter where the engine is installed.

### 3. Optional: AI-enriched remediation

```bash
cp .env.example .env
# edit .env with your provider key
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUDITOR_LLM_PROVIDER` | `groq` | `groq` / `openai` / `openrouter` / `ollama` / `custom` |
| `AUDITOR_LLM_API_KEY` | — | Provider API key (`GROQ_API_KEY` also works). Free Groq keys: [console.groq.com](https://console.groq.com) |
| `AUDITOR_LLM_MODEL` | provider default | e.g. `llama-3.3-70b-versatile` |
| `AUDITOR_LLM_BASE_URL` | provider default | Any OpenAI-compatible endpoint (including local Ollama) |
| `AUDITOR_PYTHON` | `python3` | Interpreter the dashboard spawns for the engine |
| `AUDITOR_ALLOWED_ROOTS` | your home dir | Colon-separated dirs the dashboard may scan |

There is **no database**. Scan history is written by the engine to `~/.auditor/history/` and is shared by CLI and dashboard.

Offline LLM testing: `python scripts/mock_llm_server.py` (listens on `127.0.0.1:9911`), then point `AUDITOR_LLM_BASE_URL` at it.

---

## CLI reference (short)

```bash
audit scan <path> [--format table|json|md] [--checks secrets,auth,...] \
  [--min-severity high] [--fail-on high] [--llm auto|on|off] [-q]

audit explain <rule-id>     # knowledge-base detail for a rule
audit fix <path>            # apply safe auto-fixes (interactive)
audit info                  # version, available checks, LLM status
```

Exit codes: `0` = clean / below threshold, `1` = findings at or above `--fail-on`, `2` = usage / runtime error. Ideal for CI.

Full rule catalog, design notes, and options: [auditor-engine/README.md](auditor-engine/README.md).

---

## Architecture notes

- **Dashboard → engine coupling**: `POST /api/scan` runs `python -m auditor scan <path> --format json`. The JSON contract is the only interface (same one a GitHub Action or pre-commit hook would use).
- **Path safety**: scans are restricted to `AUDITOR_ALLOWED_ROOTS` (default: home directory). Tighten this if you ever expose the dashboard beyond localhost. Do **not** expose `audit fix` through a public UI.
- **Deterministic first**: scanners decide what is vulnerable. The LLM never “finds” issues; it only enriches remediation for high-severity findings when configured.

---

## Project layout

```
├── auditor-engine/          # Python package + CLI
│   ├── auditor/
│   │   ├── scanners/        # 7 categories
│   │   ├── knowledge/       # rules.json (OWASP/CWE guidance)
│   │   ├── llm/             # optional enrichment
│   │   ├── fixer/
│   │   └── reporter/
│   └── pyproject.toml
├── demo-apps/
│   └── vulnerable-chatbot/  # intentional vulnerabilities
├── scripts/
│   └── mock_llm_server.py   # offline LLM testing
├── src/                     # Next.js dashboard (App Router)
└── .env.example
```

---

## License

MIT (see engine package metadata). Use responsibly — the demo app is intentionally insecure and must not be deployed.
