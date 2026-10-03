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
    def __init__(self, log_path: str | None = None, script: list | None = None):
        self.requests: list[dict] = []
        self.log_path = log_path
        self.script = list(script or [])
        self.lock = threading.Lock()

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
            rule = recorder.record(entry)
            payload = json.dumps(rule.get("json", {})).encode() if "json" in rule else rule.get("body", "").encode()
            self.send_response(rule.get("status", 200))
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
    a = ap.parse_args()
    rec = Recorder(a.log, json.load(open(a.script)) if a.script else None)
    srv = make_server(rec, a.port)
    print(srv.server_address[1], flush=True)
    sys.stdout.flush()
    srv.serve_forever()
