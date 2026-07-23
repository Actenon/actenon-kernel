from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from actenon.ui.trace_viewer.trace_loader import (
    find_run,
    load_trace_index,
    repo_root_from_viewer,
    resolve_artifact_roots,
    run_summaries,
)


STATIC_DIR = Path(__file__).resolve().parent / "static"


class TraceViewerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, repo_root: Path, artifact_roots: tuple[Path, ...], **kwargs: Any) -> None:
        self.repo_root = repo_root
        self.artifact_roots = artifact_roots
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/runs":
            index = load_trace_index(resolve_artifact_roots(self.repo_root, self.artifact_roots))
            self._send_json({"generated_at": index["generated_at"], "artifact_roots": index["artifact_roots"], "runs": run_summaries(index)})
            return
        if parsed.path.startswith("/api/runs/"):
            run_id = parsed.path.removeprefix("/api/runs/")
            index = load_trace_index(resolve_artifact_roots(self.repo_root, self.artifact_roots))
            run = find_run(index, run_id)
            if run is None:
                self.send_error(HTTPStatus.NOT_FOUND, f"Unknown run id: {run_id}")
                return
            self._send_json(run)
            return
        if parsed.path in {"", "/"}:
            self.path = "/index.html"
        super().do_GET()

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_json(self, payload: Any) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the read-only local artifact viewer for kernel traces.")
    parser.add_argument(
        "--artifact-root",
        action="append",
        default=[],
        help="Artifact root to load. If omitted, the viewer uses artifacts/local_proof and artifacts/portable_local_proof when present.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind.")
    parser.add_argument("--port", default=8421, type=int, help="Port to serve on.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    repo_root = repo_root_from_viewer()
    config = resolve_artifact_roots(repo_root, args.artifact_root or None)
    handler = lambda *handler_args, **handler_kwargs: TraceViewerHandler(  # noqa: E731
        *handler_args,
        repo_root=config.repo_root,
        artifact_roots=config.roots,
        **handler_kwargs,
    )

    server = ThreadingHTTPServer((args.host, args.port), handler)
    print("Actenon Kernel OSS Trace Viewer")
    print("Local, read-only, artifact-based, and kernel-scoped.")
    print(f"Serving on http://{args.host}:{args.port}")
    if config.roots:
        print("Artifact roots:")
        for root in config.roots:
            print(f" - {root}")
        print("Inspect first: Action Intent and PCCB, then Receipt or Refusal, then replay and protected-endpoint state, then execution flow.")
    else:
        print("No artifact roots found. Generate artifacts first with bash ./scripts/first_run.sh.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
