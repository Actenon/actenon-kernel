"""CrewAI protected tool example.

The important property of this example is boundary placement: proof
verification happens inside the CrewAI tool execution path before any protected
action runs.
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
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - optional integration dependency
    raise SystemExit("Install CrewAI first: pip install -r requirements.txt") from exc


EXAMPLE_ROOT = Path(__file__).resolve().parent
DELEGATED_WRONG_AUDIENCE_ID = "crewai-delegated-boundary"


class ProtectedHelloToolInput(BaseModel):
    intent_json: str | None = Field(
        default=None,
        description="Optional Action Intent JSON string. Omit to use the local proof fixture.",
    )
    pccb_json: str | None = Field(
        default=None,
        description="Optional PCCB JSON string. Omit to use the local proof fixture.",
    )
    audience_id: str = Field(
        default=DEFAULT_AUDIENCE_ID,
        description=(
            "Protected endpoint audience identity for this tool. "
            "Change it to demonstrate delegated-boundary refusal."
        ),
    )


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


class ProtectedHelloCrewAITool(BaseTool):
    """CrewAI tool whose `_run` method is the protected execution edge."""

    name: str = "protected_hello_read"
    description: str = (
        "Verify an Action Intent and PCCB inside the CrewAI tool before reading the "
        "protected hello-world resource. Returns an Actenon receipt on success or an "
        "Actenon refusal when execution is blocked."
    )
    args_schema: type[BaseModel] = ProtectedHelloToolInput

    def _run(
        self,
        intent_json: str | None = None,
        pccb_json: str | None = None,
        audience_id: str = DEFAULT_AUDIENCE_ID,
    ) -> dict[str, Any]:
        request_id = build_request_id("crewai")
        try:
            # In a multi-agent crew, other agents may inspect, summarize, or forward the
            # same artifacts. That does not authorize this tool call. The protected tool
            # is the execution edge and must verify proof again against its own audience.
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


def _read_optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.read_text(encoding="utf-8")


def _tool_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    audience_id = DEFAULT_AUDIENCE_ID
    if args.scenario == "delegated-audience-mismatch":
        audience_id = DELEGATED_WRONG_AUDIENCE_ID
    return {
        "intent_json": _read_optional_text(args.intent_file),
        "pccb_json": _read_optional_text(args.pccb_file),
        "audience_id": audience_id,
    }


def run_direct(args: argparse.Namespace) -> None:
    tool = ProtectedHelloCrewAITool()
    result = tool.run(**_tool_kwargs(args))
    print(json.dumps(result, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="CrewAI protected tool example.")
    parser.add_argument(
        "--scenario",
        choices=("success", "delegated-audience-mismatch"),
        default="success",
        help="Choose a deterministic success or delegated-boundary refusal demonstration.",
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
