"""LangChain protected tool example.

The important property of this example is boundary placement: proof
verification happens inside the LangChain tool execution path before any
protected action runs.
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
    from langchain.agents import create_agent
    from langchain.tools import BaseTool
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - optional integration dependency
    raise SystemExit("Install LangChain first: pip install -r requirements.txt") from exc


EXAMPLE_ROOT = Path(__file__).resolve().parent
DEFAULT_AGENT_MODEL = "openai:gpt-4.1-mini"
AUDIENCE_MISMATCH_ID = "langchain-wrong-audience"


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
            "Change it to demonstrate audience-mismatch refusal."
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


class ProtectedHelloLangChainTool(BaseTool):
    """LangChain tool whose `_run` method is the protected execution edge."""

    name: str = "protected_hello_read"
    description: str = (
        "Verify an Action Intent and PCCB inside the tool execution path, then read the "
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
        request_id = build_request_id("langchain")
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


def _read_optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.read_text(encoding="utf-8")


def _direct_tool_input(args: argparse.Namespace) -> dict[str, Any]:
    audience_id = DEFAULT_AUDIENCE_ID
    if args.scenario == "audience-mismatch":
        audience_id = AUDIENCE_MISMATCH_ID
    return {
        "intent_json": _read_optional_text(args.intent_file),
        "pccb_json": _read_optional_text(args.pccb_file),
        "audience_id": audience_id,
    }


def run_direct(args: argparse.Namespace) -> None:
    tool = ProtectedHelloLangChainTool()
    result = tool.invoke(_direct_tool_input(args))
    print(json.dumps(result, indent=2, sort_keys=True))


def run_agent(args: argparse.Namespace) -> None:
    tool = ProtectedHelloLangChainTool()
    system_prompt = (
        "You have one protected execution tool. Use it when asked to read the protected "
        "hello-world resource. Return the tool result without adding approval logic or "
        "inventing extra execution steps."
    )
    agent = create_agent(
        model=args.model,
        tools=[tool],
        system_prompt=system_prompt,
    )
    tool_args = _direct_tool_input(args)
    if args.prompt:
        prompt = args.prompt
    elif args.scenario == "audience-mismatch":
        prompt = (
            "Call protected_hello_read with audience_id set to "
            f"'{tool_args['audience_id']}' and return the result."
        )
    else:
        prompt = "Call protected_hello_read with its default local proof inputs and return the result."
    result = agent.invoke({"messages": [{"role": "user", "content": prompt}]})
    final_message = result["messages"][-1]
    output = {
        "message_count": len(result["messages"]),
        "final_message_type": final_message.__class__.__name__,
        "final_content": getattr(final_message, "content", None),
    }
    print(json.dumps(output, indent=2, sort_keys=True, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(description="LangChain protected tool example.")
    parser.add_argument(
        "--mode",
        choices=("direct", "agent"),
        default="direct",
        help="Use 'direct' for a local tool invocation or 'agent' to route through a LangChain agent.",
    )
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
    parser.add_argument(
        "--model",
        default=DEFAULT_AGENT_MODEL,
        help="LangChain agent model string for --mode agent.",
    )
    parser.add_argument(
        "--prompt",
        help="Optional user prompt for --mode agent. Omit to use the built-in protected-tool prompt.",
    )
    args = parser.parse_args()

    if args.mode == "agent":
        run_agent(args)
    else:
        run_direct(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
