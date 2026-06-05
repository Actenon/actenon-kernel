"""LlamaIndex protected tool example.

The important property of this example is boundary placement: the wrapped
function is the protected execution edge, so proof verification happens there
before any protected action runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from actenon.core import ContractValidationError  # noqa: E402
from actenon.demo.portable_local_proof import FIXED_BASE_TIME  # noqa: E402
from actenon.receipts import RefusalFactory  # noqa: E402
from examples.integration_support import (  # noqa: E402
    DEFAULT_AUDIENCE_ID,
    build_request_id,
    execute_protected_hello,
    parse_optional_json_mapping,
)

try:  # noqa: E402
    from llama_index.core.tools import FunctionTool
except ImportError as exc:  # pragma: no cover - optional integration dependency
    raise SystemExit("Install LlamaIndex first: pip install -r requirements.txt") from exc


EXAMPLE_ROOT = Path(__file__).resolve().parent
AUDIENCE_MISMATCH_ID = "llamaindex-wrong-audience"


def _build_contract_refusal(*, request_id: str, exc: ContractValidationError) -> dict[str, Any]:
    refusal = RefusalFactory(refusal_id_factory=lambda: f"rfsl_{request_id}").create_from_exception(
        exc,
        occurred_at=FIXED_BASE_TIME,
        intent=None,
        context=None,
    )
    return {
        "ok": False,
        "refusal": refusal.to_dict(),
    }


def protected_hello_read(
    intent_json: str | None = None,
    pccb_json: str | None = None,
    audience_id: str = DEFAULT_AUDIENCE_ID,
) -> dict[str, Any]:
    """Verify proof inside the wrapped function before allowing the protected action."""

    request_id = build_request_id("llamaindex")
    try:
        outcome = execute_protected_hello(
            example_root=EXAMPLE_ROOT,
            request_id=request_id,
            intent_payload=parse_optional_json_mapping(intent_json, field_name="intent_json"),
            pccb_payload=parse_optional_json_mapping(pccb_json, field_name="pccb_json"),
            audience_id=audience_id,
        )
        return outcome.to_dict()
    except json.JSONDecodeError as exc:
        return _build_contract_refusal(
            request_id=request_id,
            exc=ContractValidationError(f"Invalid JSON supplied to the tool: {exc.msg}."),
        )
    except ContractValidationError as exc:
        return _build_contract_refusal(request_id=request_id, exc=exc)


def build_tool() -> FunctionTool:
    return FunctionTool.from_defaults(
        fn=protected_hello_read,
        name="protected_hello_read",
        description=(
            "Verify an Action Intent and PCCB inside the wrapped function before reading the "
            "protected hello-world resource. Returns an Actenon receipt on success or an "
            "Actenon refusal on failure."
        ),
        return_direct=True,
    )


def _read_optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.read_text(encoding="utf-8")


def _tool_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    audience_id = DEFAULT_AUDIENCE_ID
    if args.scenario == "audience-mismatch":
        audience_id = AUDIENCE_MISMATCH_ID
    return {
        "intent_json": _read_optional_text(args.intent_file),
        "pccb_json": _read_optional_text(args.pccb_file),
        "audience_id": audience_id,
    }


def run_direct(args: argparse.Namespace) -> None:
    tool = build_tool()
    tool_output = tool.call(**_tool_kwargs(args))
    raw_output = getattr(tool_output, "raw_output", tool_output)
    print(json.dumps(raw_output, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="LlamaIndex protected tool example.")
    parser.add_argument(
        "--scenario",
        choices=("success", "audience-mismatch"),
        default="success",
        help="Choose a deterministic success or refusal demonstration.",
    )
    parser.add_argument(
        "--intent-file",
        type=Path,
        help="Optional path to an Action Intent JSON file. Omit to use the bundled local proof fixture.",
    )
    parser.add_argument(
        "--pccb-file",
        type=Path,
        help="Optional path to a PCCB JSON file. Omit to use the bundled local proof fixture.",
    )
    args = parser.parse_args()

    run_direct(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
