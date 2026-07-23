from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT_URL = "http://127.0.0.1:9898/refunds"


def _load_request_dir(*, issue_response_path: Path | None, request_dir: Path | None) -> Path:
    if issue_response_path is not None:
        payload = json.loads(issue_response_path.read_text(encoding="utf-8"))
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, dict) or not isinstance(artifacts.get("request_dir"), str):
            raise ValueError("issue-response must include artifacts.request_dir.")
        return Path(artifacts["request_dir"])
    if request_dir is None:
        raise ValueError("either --issue-response or --request-dir is required.")
    return request_dir


def _build_execution_payload(request_dir: Path) -> dict[str, Any]:
    action_intent_path = request_dir / "action_intent.json"
    pccb_path = request_dir / "pccb.json"
    context_path = request_dir / "context.json"
    if not action_intent_path.exists():
        raise ValueError(f"request dir is missing {action_intent_path.name}: {request_dir}")
    if not pccb_path.exists():
        raise ValueError(f"request dir is missing {pccb_path.name}: {request_dir}")
    payload = {
        "action_intent": json.loads(action_intent_path.read_text(encoding="utf-8")),
        "pccb": json.loads(pccb_path.read_text(encoding="utf-8")),
    }
    if context_path.exists():
        stored_context = json.loads(context_path.read_text(encoding="utf-8"))
        if isinstance(stored_context, dict):
            replayable_context: dict[str, str] = {}
            if isinstance(stored_context.get("now"), str):
                replayable_context["now"] = stored_context["now"]
            if isinstance(stored_context.get("request_id"), str):
                replayable_context["request_id"] = stored_context["request_id"]
            if replayable_context:
                payload["context"] = replayable_context
    return payload


def _post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = Request(url, method="POST")
    request.add_header("Content-Type", "application/json")
    request.data = json.dumps(payload).encode("utf-8")
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
            body = response.read()
    except HTTPError as exc:
        status = exc.code
        body = exc.read()
    except URLError as exc:
        raise RuntimeError(f"Could not reach protected endpoint: {exc.reason}") from exc
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("Protected endpoint did not return a JSON object.")
    return status, parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Call the local protected refund endpoint from issuer artifacts.")
    parser.add_argument("--issue-response", type=Path, default=None, help="Saved JSON response from POST /v1/intents.")
    parser.add_argument("--request-dir", type=Path, default=None, help="Request artifact directory with action_intent.json and pccb.json.")
    parser.add_argument("--endpoint-url", default=DEFAULT_ENDPOINT_URL, help="Protected endpoint URL.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON instead of human-readable output.")
    args = parser.parse_args(argv)

    try:
        request_dir = _load_request_dir(issue_response_path=args.issue_response, request_dir=args.request_dir)
        payload = _build_execution_payload(request_dir)
        status, response = _post_json(args.endpoint_url, payload)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"ok": False, "summary": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"Protected endpoint call failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(response, indent=2, sort_keys=True))
        return 0

    receipt = response.get("receipt")
    refusal = response.get("refusal")
    artifacts = response.get("artifacts", {})
    outcome = "executed" if response.get("ok") else "refused"
    print(f"Protected endpoint outcome: {outcome} (HTTP {status})")
    if isinstance(receipt, dict):
        print(f"Receipt: {receipt.get('receipt_id')} ({receipt.get('outcome')})")
    if isinstance(refusal, dict):
        print(f"Refusal: {refusal.get('refusal_code')}")
    if isinstance(artifacts, dict):
        if isinstance(artifacts.get("receipt"), str) and artifacts["receipt"]:
            print(f"Receipt artifact: {artifacts['receipt']}")
        if isinstance(artifacts.get("refusal"), str) and artifacts["refusal"]:
            print(f"Refusal artifact: {artifacts['refusal']}")
        if isinstance(artifacts.get("state_path"), str):
            print(f"Protected state: {artifacts['state_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
