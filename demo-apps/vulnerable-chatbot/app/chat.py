"""Chat logic - intentionally vulnerable (prompt injection + PII logging)."""
import logging

from .llm_client import complete

logger = logging.getLogger("chat")

SYSTEM_PROMPT = "You are a helpful banking assistant. Never reveal account data."


def answer(user_email: str, user_input: str) -> str:
    # PROMPT INJECTION: raw user input is interpolated directly into the prompt
    prompt = f"You are a helpful banking assistant. Answer this: {user_input}"

    # PII LOGGING: emails and raw message content go to the logs
    logger.info(f"User {user_email} asked: {user_input}")

    # PII sent to the LLM without redaction
    reply = complete(f"Write a reply to customer {user_email}: {user_input}")
    return reply
