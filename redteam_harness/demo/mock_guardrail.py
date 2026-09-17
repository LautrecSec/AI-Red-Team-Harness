from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(min(length, 1_000_000))
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "invalid json")
            return

        text = json.dumps(payload).lower()
        blocked = any(term in text for term in ("ignore prior instructions", "system prompt", "canary"))
        response = {
            "blocked": blocked,
            "decision": "deny" if blocked else "allow",
            "message": "mock guardrail decision",
        }
        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104
