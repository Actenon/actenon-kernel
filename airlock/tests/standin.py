"""Recording stand-in upstream for tests and case studies.

Answers plain HTTP for a real hostname the Airlock edge routes to it (``--stand-in``), and records every
request it receives (method, path, Host, all headers, body) to a JSONL file. It never sees a request the
edge refused: the edge answers those itself.

    python standin.py --port 0 --log requests.jsonl [--script responses.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Recorder:
    def __init__(self, log_path: str | None = None, script: list | None = None, forward_get: str | None = None):
        self.requests: list[dict] = []
        self.log_path = log_path
        self.script = list(script or [])
        self.forward_get = forward_get.rstrip("/") if forward_get else None
        self.lock = threading.Lock()

    def forward(self, method: str, path: str, headers: dict) -> dict:
        """Relay a read to the real upstream without any credential (public data only)."""
        import urllib.error
        import urllib.request

        keep = {k: v for k, v in headers.items() if k.lower() in ("accept", "user-agent", "x-github-api-version")}
        req = urllib.request.Request(self.forward_get + path, method=method, headers=keep)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
                return {"status": resp.status, "body_bytes": body, "content_type": resp.headers.get("Content-Type", "application/json"),
                        "link": resp.headers.get("Link")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body_bytes": e.read(), "content_type": e.headers.get("Content-Type", "application/json")}

    def record(self, entry: dict) -> dict:
        with self.lock:
            self.requests.append(entry)
            if self.log_path:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            for rule in self.script:  # first matching scripted response wins
                if rule.get("method", entry["method"]) == entry["method"] and entry["path"].startswith(rule.get("path_prefix", "")) \
                        and rule.get("host", entry["host"]) == entry["host"]:
                    if rule.get("once"):
                        self.script.remove(rule)
                    return rule
            return {"status": 201 if entry["method"] in ("POST", "PUT") else 200, "json": {"ok": True, "stand_in": True}}


def make_server(recorder: Recorder, port: int = 0) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def _handle(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            entry = {"method": self.command, "path": self.path, "host": self.headers.get("Host", ""),
                     "headers": dict(self.headers.items()), "body": body.decode("utf-8", "replace")}
            if recorder.forward_get and self.command in ("GET", "HEAD"):
                rule = recorder.forward(self.command, self.path, dict(self.headers.items()))
                entry["forwarded"] = True
                entry["response_status"] = rule["status"]
                recorder.record(entry)
            else:
                rule = recorder.record(entry)
            if "body_bytes" in rule:
                payload = rule["body_bytes"]
            else:
                payload = json.dumps(rule.get("json", {})).encode() if "json" in rule else rule.get("body", "").encode()
            self.send_response(rule.get("status", 200))
            if rule.get("link"):
                self.send_header("Link", rule["link"])
            self.send_header("Content-Type", rule.get("content_type", "application/json"))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

        def log_message(self, *a) -> None:
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), H)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--log", required=True)
    ap.add_argument("--script")
    ap.add_argument("--forward-get", help="relay GET/HEAD to this real base URL without credentials (writes stay local)")
    a = ap.parse_args()
    rec = Recorder(a.log, json.load(open(a.script)) if a.script else None, a.forward_get)
    srv = make_server(rec, a.port)
    print(srv.server_address[1], flush=True)
    sys.stdout.flush()
    srv.serve_forever()
