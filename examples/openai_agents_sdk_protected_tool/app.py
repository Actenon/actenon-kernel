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
from examples.integration_support import (  # noqa: E402
    build_request_id,
    execute_protected_hello,
    parse_optional_json_mapping,
)

try:  # noqa: E402
    from agents import Agent, Runner, function_tool
except ImportError:  # pragma: no cover - optional integration dependency
    Agent = None
    Runner = None
    function_tool = None


EXAMPLE_ROOT = Path(__file__).resolve().parent


def protected_hello_tool_impl(intent_json: str | None = None, pccb_json: str | None = None) -> dict[str, Any]:
    """Verify local proof artifacts before allowing a protected hello-world action."""

    outcome = execute_protected_hello(
        example_root=EXAMPLE_ROOT,
        request_id=build_request_id("openai_agents"),
        intent_payload=parse_optional_json_mapping(intent_json, field_name="intent_json"),
        pccb_payload=parse_optional_json_mapping(pccb_json, field_name="pccb_json"),
    )
    return outcome.to_dict()


if function_tool is not None:  # pragma: no branch - small optional integration surface
    protected_hello_tool = function_tool(protected_hello_tool_impl)
else:  # pragma: no cover - exercised only when dependency is missing
    protected_hello_tool = None


def run_direct() -> None:
    result = protected_hello_tool_impl()
    print(json.dumps(result, indent=2, sort_keys=True))


def run_agent() -> None:
    if Agent is None or Runner is None or protected_hello_tool is None:
        raise SystemExit("Install the OpenAI Agents SDK first: pip install -r requirements.txt")
    agent = Agent(
        name="Protected Hello Agent",
        model="gpt-5-nano",
        instructions=(
            "You have one protected tool. Use it when asked to read the hello-world protected resource. "
            "Return the tool JSON directly."
        ),
        tools=[protected_hello_tool],
    )
    result = Runner.run_sync(agent, "Read the protected hello resource using local proof mode.")
    print(result.final_output)


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAI Agents SDK protected tool example.")
    parser.add_argument(
        "--mode",
        choices=("direct", "agent"),
        default="direct",
        help="Use 'direct' for a local no-network tool invocation or 'agent' to run through the OpenAI Agents SDK.",
    )
    args = parser.parse_args()

    try:
        if args.mode == "agent":
            run_agent()
        else:
            run_direct()
    except ContractValidationError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": exc.refusal_code,
                    "message": exc.message,
                    "details": exc.details,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
