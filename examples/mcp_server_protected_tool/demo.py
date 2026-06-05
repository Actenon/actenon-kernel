"""Run the MCP hero path locally without an MCP client."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from .proof_gate import EXAMPLE_ROOT, build_demo_tool_call, invoke_protected_tool, supported_tool_names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m examples.mcp_server_protected_tool.demo",
        description="Run a local agent -> MCP tool call -> Actenon proof gate -> VAR emission demo.",
    )
    parser.add_argument(
        "--tool",
        default="filesystem.delete",
        choices=supported_tool_names(),
        help="Consequential MCP tool to call. Defaults to filesystem.delete.",
    )
    parser.add_argument(
        "--scenario",
        default="allow",
        choices=("allow", "refuse", "missing-proof"),
        help="Demo scenario. 'allow' executes, 'refuse' is blocked by Preflight policy, and 'missing-proof' is blocked by the proof gate.",
    )
    parser.add_argument("--json", action="store_true", help="Emit only structured JSON.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    example_root = EXAMPLE_ROOT

    scenario = "refuse" if args.scenario == "refuse" else "allow"
    demo_call = build_demo_tool_call(args.tool, scenario=scenario)
    outcome = invoke_protected_tool(
        args.tool,
        intent_payload=demo_call.intent.to_dict(),
        pccb_payload=None if args.scenario == "missing-proof" else demo_call.pccb.to_dict(),
        preflight_evidence=demo_call.preflight_evidence,
        request_id=f"demo_{args.tool.replace('.', '_')}_{args.scenario.replace('-', '_')}",
        example_root=example_root,
    )
    payload = outcome.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("MCP hero path demo.")
        print("Flow: agent -> MCP tool call -> Actenon proof gate -> tool executes/refuses -> VAR emitted")
        print(f"Tool: {payload['tool_name']}")
        print(f"Preflight: {payload['preflight']['outcome']} ({payload['preflight']['reason_code']})")
        print(f"Outcome: {'executed' if payload['ok'] else 'refused'}")
        if "receipt" in payload:
            print(f"Receipt: {payload['receipt']['receipt_id']}")
        if "refusal" in payload:
            print(f"Refusal: {payload['refusal']['refusal_code']}")
        print(f"VAR: {payload['var']['artifact_kind']} {payload['var']['artifact_id']}")
        print(f"Artifacts: {payload['artifact_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
