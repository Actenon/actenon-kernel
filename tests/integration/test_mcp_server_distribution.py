"""WO-18: the packaged, connectable MCP server.

These tests drive `actenon.mcp_server` the way a client does — through the
public tool functions and the argument parser — rather than reaching into
the FastMCP internals. The stdio wire itself is covered by the quickstart
transcript in docs/integrations/MCP_QUICKSTART.md.
"""

from __future__ import annotations

import copy
import json
import re
import shlex
import socket
import unittest
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory

# The server module imports cleanly without the extra; only build_server()
# needs `mcp`. Skip the whole module when it is absent so a base install
# stays green, and install [mcp] in CI so these actually run.
requires_mcp = unittest.skipUnless(
    find_spec("mcp") is not None,
    "the packaged MCP server requires the 'mcp' extra",
)

from actenon.mcp_server import (
    DEMO_BANNER,
    DecisionLog,
    build_demo_gate,
    build_server,
    main,
)

REFUND = {
    "action_name": "refund.issue",
    "capability": "payments.refund",
    "parameters": {"amount_cents": 2500, "currency": "USD"},
    "target_type": "payment",
    "target_id": "pay_9f2c",
}

ROOT = Path(__file__).resolve().parents[2]

# The launch command every copy-paste form in the docs must resolve to. uvx
# only reads its own options before the command name, so `--from` has to
# precede `actenon-mcp`; placed after it, uvx runs the wrong command.
LAUNCH_ARGV = ["uvx", "--from", "actenon-kernel[mcp]", "actenon-mcp", "--demo"]
LAUNCH_DOCS = ("README.md", "docs/integrations/MCP_QUICKSTART.md")


def _tools(demo: bool = True) -> dict:
    gate, signer = build_demo_gate()
    server = build_server(demo=demo, gate=gate, signer=signer, audience="mcp:test")
    # FastMCP keeps the registered callables; call them directly.
    return {name: tool.fn for name, tool in server._tool_manager._tools.items()}


@requires_mcp
class McpServerToolSurfaceTests(unittest.TestCase):
    def test_three_tools_always_present(self) -> None:
        for demo in (True, False):
            with self.subTest(demo=demo):
                names = set(_tools(demo))
                self.assertLessEqual(
                    {"actenon_verify", "actenon_gate", "actenon_receipt"}, names
                )

    def test_demo_grant_exists_only_in_demo_mode(self) -> None:
        self.assertIn("actenon_demo_grant", _tools(demo=True))
        self.assertNotIn("actenon_demo_grant", _tools(demo=False))

    def test_every_demo_tool_description_carries_the_banner(self) -> None:
        gate, signer = build_demo_gate()
        server = build_server(demo=True, gate=gate, signer=signer, audience="mcp:test")
        for tool in server._tool_manager._tools.values():
            with self.subTest(tool=tool.name):
                self.assertIn(DEMO_BANNER, tool.description or "")

    def test_production_tool_descriptions_do_not_claim_demo(self) -> None:
        gate, signer = build_demo_gate()
        server = build_server(demo=False, gate=gate, signer=signer, audience="mcp:test")
        for tool in server._tool_manager._tools.values():
            with self.subTest(tool=tool.name):
                self.assertNotIn(DEMO_BANNER, tool.description or "")


@requires_mcp
class McpServerDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tools = _tools(demo=True)

    def test_gate_refuses_without_proof_and_explains_why(self) -> None:
        result = self.tools["actenon_gate"](**REFUND)
        self.assertEqual("REFUSED", result["outcome"])
        self.assertEqual("PCCB_REQUIRED", result["reason_code"])
        # The point of this server: the model can see WHY, in English.
        self.assertTrue(result["reason"])
        self.assertIn("next_step", result)

    def test_scoped_proof_allows_the_exact_action(self) -> None:
        granted = self.tools["actenon_demo_grant"](**REFUND)
        result = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        self.assertEqual("ALLOW", result["outcome"])
        self.assertTrue(result["allowed"])
        self.assertIn("receipt_id", result)

    def test_widening_the_parameters_is_refused(self) -> None:
        granted = self.tools["actenon_demo_grant"](**REFUND)
        tampered = copy.deepcopy(granted["intent"])
        tampered["action"]["parameters"]["amount_cents"] = 500000
        result = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=tampered
        )
        self.assertEqual("REFUSED", result["outcome"])
        self.assertEqual("ACTION_MISMATCH", result["reason_code"])

    def test_single_use_proof_cannot_be_replayed(self) -> None:
        granted = self.tools["actenon_demo_grant"](**REFUND)
        first = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        self.assertEqual("ALLOW", first["outcome"])
        second = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        self.assertEqual("REFUSED", second["outcome"])
        self.assertEqual("DUPLICATE_REPLAY", second["reason_code"])

    def test_verify_is_pure_and_emits_no_receipt(self) -> None:
        granted = self.tools["actenon_demo_grant"](**REFUND)
        verified = self.tools["actenon_verify"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        self.assertEqual("VALID", verified["outcome"])
        # Verification consumed no replay state: the gate still allows.
        gated = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        self.assertEqual("ALLOW", gated["outcome"])
        # And it recorded nothing in the decision log before the gate ran.
        listing = self.tools["actenon_receipt"]()
        self.assertEqual(1, listing["chain_length"])

    def test_verify_reports_a_typed_outcome_for_a_bad_proof(self) -> None:
        result = self.tools["actenon_verify"](**REFUND, proof={"nonsense": True})
        self.assertEqual("INVALID", result["outcome"])
        self.assertEqual("PROOF_MALFORMED", result["reason_code"])
        self.assertTrue(result["reason"])

    def test_receipt_returns_the_artifact_and_its_chain_position(self) -> None:
        granted = self.tools["actenon_demo_grant"](**REFUND)
        allowed = self.tools["actenon_gate"](
            **REFUND, proof=granted["proof"], intent=granted["intent"]
        )
        fetched = self.tools["actenon_receipt"](artifact_id=allowed["receipt_id"])
        self.assertEqual("OK", fetched["outcome"])
        self.assertEqual("executed", fetched["artifact"]["outcome"])
        self.assertEqual(allowed["chain"]["entry_hash"], fetched["chain"]["entry_hash"])

    def test_unknown_receipt_is_a_typed_not_found(self) -> None:
        result = self.tools["actenon_receipt"](artifact_id="rcpt_does_not_exist")
        self.assertEqual("NOT_FOUND", result["outcome"])
        self.assertEqual("ARTIFACT_NOT_FOUND", result["reason_code"])


class DecisionLogChainTests(unittest.TestCase):
    def test_each_entry_commits_to_its_predecessor(self) -> None:
        log = DecisionLog()
        first = log.append(kind="refusal", artifact={"refusal_id": "rfsl_1"})
        second = log.append(kind="receipt", artifact={"receipt_id": "rcpt_1"})
        self.assertIsNone(first["previous_entry_hash"])
        self.assertEqual(first["entry_hash"]["value"], second["previous_entry_hash"])
        self.assertNotEqual(first["entry_hash"]["value"], second["entry_hash"]["value"])

    def test_the_same_artifact_hashes_differently_at_a_different_position(self) -> None:
        # A chain that only hashed the artifact would let entries be reordered.
        a, b = DecisionLog(), DecisionLog()
        b.append(kind="refusal", artifact={"refusal_id": "rfsl_0"})
        first = a.append(kind="receipt", artifact={"receipt_id": "rcpt_1"})
        later = b.append(kind="receipt", artifact={"receipt_id": "rcpt_1"})
        self.assertNotEqual(first["entry_hash"]["value"], later["entry_hash"]["value"])


class FailClosedTests(unittest.TestCase):
    def test_non_demo_without_a_key_refuses_to_start(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main([])
        message = str(raised.exception)
        self.assertIn("no signing material configured", message)
        self.assertIn("--demo", message)

    def test_non_demo_with_a_missing_key_file_refuses_to_start(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["--key-file", "/nonexistent/actenon-mcp.key"])
        self.assertIn("not found", str(raised.exception))

    def test_non_demo_with_an_empty_key_file_refuses_to_start(self) -> None:
        with TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty.key"
            empty.write_bytes(b"")
            with self.assertRaises(SystemExit) as raised:
                main(["--key-file", str(empty)])
        self.assertIn("empty", str(raised.exception))

    def test_demo_is_refused_in_a_production_like_environment(self) -> None:
        import os

        os.environ["ACTENON_ENV"] = "production"
        try:
            with self.assertRaises(SystemExit) as raised:
                main(["--demo"])
        finally:
            del os.environ["ACTENON_ENV"]
        self.assertIn("production", str(raised.exception).lower())


@requires_mcp
class DemoModeIsOfflineTests(unittest.TestCase):
    def test_building_the_demo_server_opens_no_socket(self) -> None:
        """Demo mode must need no network. Fail the test if it opens one."""

        real_socket = socket.socket

        def forbidden(*args, **kwargs):  # pragma: no cover - only on regression
            raise AssertionError("demo mode attempted a network connection")

        socket.socket = forbidden
        try:
            gate, signer = build_demo_gate()
            server = build_server(
                demo=True, gate=gate, signer=signer, audience="mcp:test"
            )
            tools = {n: t.fn for n, t in server._tool_manager._tools.items()}
            granted = tools["actenon_demo_grant"](**REFUND)
            allowed = tools["actenon_gate"](
                **REFUND, proof=granted["proof"], intent=granted["intent"]
            )
        finally:
            socket.socket = real_socket
        self.assertEqual("ALLOW", allowed["outcome"])

    def test_each_demo_process_gets_a_different_ephemeral_key(self) -> None:
        gate_a, _ = build_demo_gate()
        gate_b, _ = build_demo_gate()
        intent = gate_a.build_action(
            "refund.issue",
            "payments.refund",
            {"amount_cents": 2500},
            target_type="payment",
            target_id="pay_9f2c",
        )
        proof = gate_a.mint_proof(intent)
        # A proof minted by one demo process must not verify in another.
        outcome = gate_b.protect(intent, proof=proof, side_effect=lambda **kw: {})
        self.assertEqual("refused", outcome.outcome)


class DocumentedLaunchCommandTests(unittest.TestCase):
    """The launch commands people copy from the docs start the server.

    A misordered or unquoted command does not fail here; it fails inside the
    user's MCP client as a closed connection, or in their shell. Pin every
    documented form to one argv. Plain text parsing, so no `mcp` extra needed.
    """

    def _docs(self) -> dict[str, str]:
        return {name: (ROOT / name).read_text(encoding="utf-8") for name in LAUNCH_DOCS}

    def test_mcp_client_config_blocks_launch_the_server(self) -> None:
        for name, text in self._docs().items():
            blocks = [
                json.loads(block)
                for block in re.findall(r"```json\n(.*?)```", text, re.DOTALL)
                if '"mcpServers"' in block
            ]
            with self.subTest(doc=name):
                self.assertTrue(blocks, "no mcpServers config block found")
                for block in blocks:
                    for server in block["mcpServers"].values():
                        self.assertEqual(
                            LAUNCH_ARGV, [server["command"], *server["args"]]
                        )

    def test_claude_code_one_liner_launches_the_server(self) -> None:
        for name, text in self._docs().items():
            lines = [
                line for line in text.splitlines() if line.startswith("claude mcp add ")
            ]
            with self.subTest(doc=name):
                self.assertTrue(lines, "no `claude mcp add` one-liner found")
                for line in lines:
                    argv = shlex.split(line)
                    self.assertEqual(LAUNCH_ARGV, argv[argv.index("--") + 1 :])
                    # Unquoted, zsh treats [mcp] as a glob and aborts.
                    self.assertIn("'actenon-kernel[mcp]'", line)


@requires_mcp
class MalformedModelInputTests(unittest.TestCase):
    """A model can hand the tools anything; every bad input is a typed refusal."""

    def setUp(self) -> None:
        self.tools = _tools()
        self.granted = self.tools["actenon_demo_grant"](**REFUND)

    def _duplicate_key_proof(self) -> str:
        raw = json.dumps(self.granted["proof"])
        # A second `nonce` member: Python's json.loads keeps the last one,
        # other parsers keep the first. The protocol requires rejection.
        return raw[:-1] + ', "nonce": ' + json.dumps(self.granted["proof"]["nonce"]) + "}"

    def test_duplicate_json_keys_in_a_proof_are_refused(self) -> None:
        for tool in ("actenon_verify", "actenon_gate"):
            with self.subTest(tool=tool):
                response = self.tools[tool](
                    **REFUND, proof=self._duplicate_key_proof(), intent=self.granted["intent"]
                )
                self.assertEqual("PROOF_MALFORMED", response["reason_code"])
                self.assertFalse(response.get("valid", response.get("allowed")))

    def test_deeply_nested_proof_is_refused(self) -> None:
        deep = "[" * 100_000 + "]" * 100_000
        for tool in ("actenon_verify", "actenon_gate"):
            with self.subTest(tool=tool):
                response = self.tools[tool](**REFUND, proof=deep, intent=self.granted["intent"])
                self.assertEqual("PROOF_MALFORMED", response["reason_code"])

    def test_malformed_intent_is_a_typed_refusal(self) -> None:
        bad_intents = (
            "not json",
            "[1, 2]",
            {"contract": "nope"},
            '{"a": 1, "a": 2}',
        )
        for tool in ("actenon_verify", "actenon_gate"):
            for intent in bad_intents:
                with self.subTest(tool=tool, intent=intent):
                    response = self.tools[tool](
                        **REFUND, proof=self.granted["proof"], intent=intent
                    )
                    self.assertEqual("REFUSED", response["outcome"])
                    self.assertEqual("INTENT_MALFORMED", response["reason_code"])
                    self.assertTrue(response["reason"])

    def test_a_rejected_input_does_not_consume_the_proof(self) -> None:
        self.tools["actenon_gate"](**REFUND, proof=self.granted["proof"], intent="not json")
        allowed = self.tools["actenon_gate"](
            **REFUND, proof=self.granted["proof"], intent=self.granted["intent"]
        )
        self.assertEqual("ALLOW", allowed["outcome"])


class DemoRefusedOutsideDevelopmentTests(unittest.TestCase):
    def test_demo_is_refused_cleanly_for_any_non_development_environment(self) -> None:
        import os

        for value in ("prd", "live", "uat", "preprod"):
            with self.subTest(ACTENON_ENV=value):
                os.environ["ACTENON_ENV"] = value
                try:
                    with self.assertRaises(SystemExit) as raised:
                        main(["--demo"])
                finally:
                    del os.environ["ACTENON_ENV"]
                self.assertIn("--demo refused", str(raised.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
