# Vulnerable Chatbot (demo target)

This "app" is intentionally riddled with security issues so the auditor
has something realistic to find. **Never copy this code.**

Expected findings include:
- Hardcoded Groq/Anthropic API keys (`app/llm_client.py`, `.env`)
- `.env` committed (not gitignored) - CONFIG/critical
- Prompt injection via f-string (`app/chat.py`)
- PII logging and PII sent to the LLM (`app/chat.py`)
- Unauthenticated FastAPI endpoints (`app/main.py`)
- CORS wildcard + debug mode (`app/main.py`)
- RAG retrieval without access control (`app/rag.py`)
- `pickle.loads`, `shell=True`, `yaml.load`, `verify=False`,
  insecure randomness, MD5 (`app/utils.py`)
- `innerHTML = model output`, unsanitized markdown (`static/render.js`)

Run the auditor against it:

    audit scan ./demo-apps/vulnerable-chatbot

or via the web dashboard.
