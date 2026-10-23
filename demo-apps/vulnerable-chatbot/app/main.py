"""API entrypoint - intentionally vulnerable (no auth, CORS wildcard, debug)."""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .chat import answer
from .rag import search_docs

logging.basicConfig(level=logging.DEBUG)

app = FastAPI(title="Vulnerable Chatbot Demo")

# CORS wide open
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# No auth dependency on a sensitive endpoint
@app.get("/admin/stats")
def admin_stats():
    return {"users": 1234, "spend": "$5,210.44"}


@app.post("/chat")
def chat_endpoint(payload: dict):
    email = payload.get("email", "anon")
    text = payload.get("message", "")
    docs = search_docs(text)
    return {"reply": answer(email, text), "context": docs}


@app.get("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
