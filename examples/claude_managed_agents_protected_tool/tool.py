"""Claude Managed Agents protected tool example.

This example demonstrates the Actenon boundary on one Anthropic-managed agent
surface without moving verification upstream into planning or orchestration.
It is an Anthropic-specific compatibility example, not a control-plane
integration and not the repository's primary hero path.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Mapping


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
    from anthropic import Anthropic
except ImportError:  # pragma: no cover - optional integration dependency
    Anthropic = None


EXAMPLE_ROOT = Path(__file__).resolve().parent
EXAMPLE_ENVIRONMENT_ID_ENV = "ANTHROPIC_MANAGED_AGENTS_ENVIRONMENT_ID"
SUCCESS_SCENARIO = "success"
AUDIENCE_MISMATCH_SCENARIO = "audience-mismatch"
SCENARIOS = (SUCCESS_SCENARIO, AUDIENCE_MISMATCH_SCENARIO)
CLAUDE_WRONG_AUDIENCE_ID = "claude-managed-agents-wrong-audience"


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


def _read_optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.read_text(encoding="utf-8")


def _coerce_optional_string(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ContractValidationError(f"{field_name} must be a JSON string when provided to the tool.")
    return value


def _coerce_scenario(value: object) -> str:
    if value is None:
        return SUCCESS_SCENARIO
    if not isinstance(value, str):
        raise ContractValidationError("scenario must be a string when provided to the tool.")
    if value not in SCENARIOS:
        supported = ", ".join(SCENARIOS)
        raise ContractValidationError(f"scenario must be one of: {supported}.")
    return value


def _audience_id_for_scenario(scenario: str) -> str:
    if scenario == AUDIENCE_MISMATCH_SCENARIO:
        return CLAUDE_WRONG_AUDIENCE_ID
    return DEFAULT_AUDIENCE_ID


def protected_hello_tool_impl(
    *,
    intent_json: str | None = None,
    pccb_json: str | None = None,
    scenario: str = SUCCESS_SCENARIO,
) -> dict[str, Any]:
    """Execute verifier-first logic inside the protected tool boundary itself.

    The managed agent can decide to call this tool, but it is not the trust
    boundary. This function is the execution edge that can actually cause the
    protected action, so proof verification must stay here.
    """

    request_id = build_request_id("claude_managed_agents")
    try:
        # Even when Anthropic's managed agent invokes this tool, the orchestration
        # layer is not the trust boundary. This function is the execution edge, so
        # this is where the Action Intent and PCCB must be verified before any
        # protected action can run.
        outcome = execute_protected_hello(
            example_root=EXAMPLE_ROOT,
            request_id=request_id,
            intent_payload=parse_optional_json_mapping(intent_json, field_name="intent_json"),
            pccb_payload=parse_optional_json_mapping(pccb_json, field_name="pccb_json"),
            audience_id=_audience_id_for_scenario(_coerce_scenario(scenario)),
        )
        return outcome.to_dict()
    except json.JSONDecodeError as exc:
        return _build_contract_refusal(
            request_id=request_id,
            exc=ContractValidationError(f"Invalid JSON supplied to the tool: {exc.msg}."),
        )
    except ContractValidationError as exc:
        return _build_contract_refusal(request_id=request_id, exc=exc)


def _build_custom_tool_definition() -> dict[str, Any]:
    return {
        "type": "custom",
        "name": "protected_hello_read",
        "description": (
            "Protected consequential read. Verify the Actenon Action Intent and PCCB inside "
            "the tool before executing. Return the raw JSON result, including the canonical "
            "Receipt on success or Refusal on blocked execution."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario": {
                    "type": "string",
                    "enum": list(SCENARIOS),
                    "description": (
                        "Use 'success' for the default local proof fixture or "
                        "'audience-mismatch' to demonstrate a deterministic refusal."
                    ),
                },
                "intent_json": {
                    "type": "string",
                    "description": (
                        "Optional Action Intent JSON string. Omit to use the bundled local proof fixture."
                    ),
                },
                "pccb_json": {
                    "type": "string",
                    "description": (
                        "Optional PCCB JSON string. Omit to use the bundled local proof fixture."
                    ),
                },
            },
        },
    }


def _build_agent_system_prompt() -> str:
    return (
        "You have one protected custom tool named protected_hello_read. "
        "Use that tool when asked to read the protected hello-world resource. "
        "Do not claim execution success unless the tool actually returns a successful Actenon receipt. "
        "If the tool returns a refusal, say the action was blocked and include the raw JSON tool result."
    )


def _build_user_message(*, scenario: str) -> str:
    if scenario == AUDIENCE_MISMATCH_SCENARIO:
        scenario_instruction = (
            "Call protected_hello_read exactly once with scenario='audience-mismatch'. "
            "After the tool returns, explain briefly that execution was blocked and include the raw JSON tool result."
        )
    else:
        scenario_instruction = (
            "Call protected_hello_read exactly once with the default local proof fixture. "
            "After the tool returns, explain briefly that execution succeeded and include the raw JSON tool result."
        )
    return (
        "This is a verifier-edge demonstration. "
        "The tool result is the canonical source of truth, not your prior reasoning or session state. "
        f"{scenario_instruction}"
    )


def _extract_agent_message_text(event: Any) -> str:
    blocks = getattr(event, "content", [])
    return "\n".join(getattr(block, "text", "") for block in blocks if getattr(block, "text", ""))


def _tool_result_from_event_input(input_payload: Mapping[str, Any]) -> dict[str, Any]:
    # Session event routing is not verification. The event payload is forwarded
    # into the protected tool implementation, which remains the execution edge.
    return protected_hello_tool_impl(
        intent_json=_coerce_optional_string(input_payload.get("intent_json"), field_name="intent_json"),
        pccb_json=_coerce_optional_string(input_payload.get("pccb_json"), field_name="pccb_json"),
        scenario=_coerce_scenario(input_payload.get("scenario")),
    )


def _delete_session_if_created(client: Any, session_id: str | None) -> dict[str, Any]:
    if session_id is None:
        return {}
    try:
        client.beta.sessions.delete(session_id)
        return {"session_deleted": True}
    except Exception as exc:  # pragma: no cover - network cleanup best effort
        return {"session_deleted": False, "session_delete_error": str(exc)}


def _archive_agent_if_created(client: Any, agent_id: str | None) -> dict[str, Any]:
    if agent_id is None:
        return {}
    try:
        client.beta.agents.archive(agent_id)
        return {"agent_archived": True}
    except Exception as exc:  # pragma: no cover - network cleanup best effort
        return {"agent_archived": False, "agent_archive_error": str(exc)}


def run_direct(args: argparse.Namespace) -> dict[str, Any]:
    return protected_hello_tool_impl(
        intent_json=_read_optional_text(args.intent_file),
        pccb_json=_read_optional_text(args.pccb_file),
        scenario=args.scenario,
    )


def run_managed(args: argparse.Namespace) -> dict[str, Any]:
    if Anthropic is None:  # pragma: no cover - optional dependency gate
        raise SystemExit("Install the Anthropic SDK first: pip install -r requirements.txt")
    if args.intent_file or args.pccb_file:
        raise SystemExit(
            "Managed mode keeps the tool invocation small and reproducible. "
            "Use --mode direct if you need to supply explicit Action Intent or PCCB files."
        )

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise SystemExit("Set ANTHROPIC_API_KEY before using --mode managed.")

    environment_id = args.environment_id or os.getenv(EXAMPLE_ENVIRONMENT_ID_ENV)
    if not environment_id:
        raise SystemExit(
            f"Provide --environment-id or set {EXAMPLE_ENVIRONMENT_ID_ENV} before using --mode managed."
        )

    client = Anthropic(api_key=api_key)
    created_agent_id: str | None = None
    session_id: str | None = None
    result: dict[str, Any] = {
        "mode": "managed",
        "scenario": args.scenario,
        "environment_id": environment_id,
    }

    try:
        if args.agent_id:
            agent_id = args.agent_id
        else:
            agent = client.beta.agents.create(
                model=args.model,
                name="Actenon Protected Tool Example",
                description=(
                    "Actenon verifier-edge example. The custom tool verifies proof inside the tool "
                    "before any protected action runs and returns a receipt or refusal JSON payload."
                ),
                system=_build_agent_system_prompt(),
                tools=[_build_custom_tool_definition()],
            )
            agent_id = agent.id
            created_agent_id = agent_id

        session = client.beta.sessions.create(
            agent=agent_id,
            environment_id=environment_id,
            title="Actenon Protected Hello Example",
        )
        session_id = session.id

        client.beta.sessions.events.send(
            session_id,
            events=[
                {
                    "type": "user.message",
                    "content": [{"type": "text", "text": _build_user_message(scenario=args.scenario)}],
                }
            ],
        )

        seen_event_ids: set[str] = set()
        tool_invocations: list[dict[str, Any]] = []
        agent_messages: list[str] = []
        deadline = time.monotonic() + args.timeout_seconds

        while time.monotonic() < deadline:
            page = client.beta.sessions.events.list(session_id, order="asc", limit=100)
            new_events = [event for event in page.data or [] if event.id not in seen_event_ids]
            if not new_events:
                time.sleep(1.0)
                continue

            for event in new_events:
                seen_event_ids.add(event.id)

                if event.type == "agent.custom_tool_use":
                    input_payload = dict(event.input)
                    tool_result = _tool_result_from_event_input(input_payload)
                    tool_invocations.append(
                        {
                            "event_id": event.id,
                            "tool_name": event.name,
                            "input": input_payload,
                            "result": tool_result,
                        }
                    )
                    client.beta.sessions.events.send(
                        session_id,
                        events=[
                            {
                                "type": "user.custom_tool_result",
                                "custom_tool_use_id": event.id,
                                "content": [
                                    {
                                        "type": "text",
                                        "text": json.dumps(tool_result, indent=2, sort_keys=True),
                                    }
                                ],
                                "is_error": False,
                            }
                        ],
                    )

                elif event.type == "agent.message":
                    text = _extract_agent_message_text(event)
                    if text:
                        agent_messages.append(text)

                elif event.type == "session.status_idle" and event.stop_reason.type == "end_turn":
                    result.update(
                        {
                            "agent_id": agent_id,
                            "session_id": session_id,
                            "tool_invocations": tool_invocations,
                            "agent_messages": agent_messages,
                            "stop_reason": event.stop_reason.type,
                        }
                    )
                    return result

            time.sleep(0.5)

        raise TimeoutError("Timed out waiting for the Claude Managed Agents session to finish.")
    finally:
        cleanup: dict[str, Any] = {}
        if not args.keep_session:
            cleanup.update(_delete_session_if_created(client, session_id))
        if created_agent_id is not None and not args.keep_agent:
            cleanup.update(_archive_agent_if_created(client, created_agent_id))
        if cleanup:
            result["cleanup"] = cleanup


def main() -> int:
    parser = argparse.ArgumentParser(description="Claude Managed Agents protected tool example.")
    parser.add_argument(
        "--mode",
        choices=("direct", "managed"),
        default="direct",
        help="Use 'direct' for a local verifier-only run or 'managed' to exercise Anthropic's managed agent beta.",
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        default=SUCCESS_SCENARIO,
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
        "--environment-id",
        help=(
            "Anthropic Managed Agents environment ID for --mode managed. "
            f"Defaults to ${EXAMPLE_ENVIRONMENT_ID_ENV} when set."
        ),
    )
    parser.add_argument(
        "--agent-id",
        help="Optional existing Anthropic Managed Agent ID to reuse instead of creating an example agent.",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Managed-agent model to use when the example creates an agent.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=60.0,
        help="Maximum time to wait for a managed-agent session to complete.",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        help="Keep the Anthropic session instead of deleting it after a managed-mode run.",
    )
    parser.add_argument(
        "--keep-agent",
        action="store_true",
        help="Keep an example-created Anthropic agent instead of archiving it after a managed-mode run.",
    )
    args = parser.parse_args()

    try:
        if args.mode == "managed":
            result = run_managed(args)
        else:
            result = run_direct(args)
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
    except TimeoutError as exc:
        print(json.dumps({"ok": False, "error": "TIMEOUT", "message": str(exc)}, indent=2, sort_keys=True))
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
