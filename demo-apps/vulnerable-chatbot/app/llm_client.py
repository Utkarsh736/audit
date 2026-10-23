"""LLM client - intentionally vulnerable (hardcoded API key)."""
from groq import Groq

# The whole point of the demo: a hardcoded secret (fake value).
client = Groq(api_key="gsk_FAKE1234567890abcdefghij")
MODEL = "llama-3.3-70b-versatile"


def complete(prompt: str, temperature: float = 0.2) -> str:
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    return resp.choices[0].message.content
