"""Utilities - intentionally vulnerable (dangerous APIs)."""
import pickle
import random
import subprocess
import yaml
import requests


def load_session(data: bytes):
    # Arbitrary code execution via crafted pickle payload
    return pickle.loads(data)


def run_report_tool(user_pattern: str):
    # Command injection: shell=True with a dynamic argument
    return subprocess.run(f"grep {user_pattern} report.txt", shell=True, capture_output=True)


def load_config(path: str):
    # Unsafe YAML loader (arbitrary object construction)
    return yaml.load(open(path))


def fetch_model_card(url: str):
    # TLS verification disabled
    return requests.get(url, verify=False)


def make_session_token(user_id: int) -> str:
    # Predictable token from a non-CSPRNG
    return f"sess-{user_id}-" + "".join(random.choices("abcdef0123456789", k=24))


def weak_checksum(data: bytes) -> str:
    import hashlib

    return hashlib.md5(data).hexdigest()
