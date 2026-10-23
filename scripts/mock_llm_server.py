"""Mock OpenAI-compatible server to test the LLM enrichment path offline."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        content = (
            "## Why this matters\nThe hardcoded key is exposed in source.\n\n"
            "## Fix\n1. Move it to `.env`.\n2. Rotate it.\n\n"
            "## Verify\nRe-run audit scan."
        )
        resp = {
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"total_tokens": 10},
        }
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9911), Handler).serve_forever()
