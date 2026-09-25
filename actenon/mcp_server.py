"""A connectable MCP server exposing the Actenon verifier.

This module packages the existing MCP adapter surface
(``actenon.adapters.mcp``) as a runnable stdio server so a developer can
connect a client in under a minute:

    uvx --from 'actenon-kernel[mcp]' actenon-mcp --demo

Three tools are always exposed:

  ``actenon_verify``   verify a proof against an intent, return the typed outcome
  ``actenon_gate``     evaluate an intent, return ALLOW or a typed refusal
  ``actenon_receipt``  return the hash-chained receipt for a prior decision

Every response carries both the machine refusal code and the
human-readable reason, because the point of this server is that a model
can *see* why it was refused and act on it.

Demo mode (``--demo``) runs with an ephemeral per-process signing key, an
in-memory replay store, and no network or configuration of any kind. It
additionally exposes ``actenon_demo_grant``, which stands in for the human
approval step a real deployment performs in ``actenon-permit``: the
verifier never issues its own authority, so the grant is a separate tool
that exists ONLY in demo mode.

Without ``--demo`` the server requires signing material and fails closed
if none is configured (WO-8 behaviour). Secrets are read from a file path
and never logged.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from secrets import token_bytes
from typing import Any

from actenon.api import ActionIntentIntakeService
from actenon.core import RefusalException
from actenon.core.json import loads_no_duplicate_keys
from actenon.gate import ActenonGate
from actenon.models import PCCB, ActionIntent, DynamicContextInput
from actenon.proof import PCCBVerifier, VerifierDisclosureMode
from actenon.proof.canonical import CANONICALIZATION_PROFILE, sha256_hex
from actenon.proof.service import default_disclosure_mode
from actenon.proof.signers.external_managed import (
    ProductionSigningGuardError,
    is_production_like_environment,
    validate_signing_backend_for_environment,
)
from actenon.proof.signers.local import build_local_proof_signer

DEMO_BANNER = "DEMO MODE — ephemeral key, not for production."
DEFAULT_AUDIENCE = "mcp:actenon-demo"
DECISION_LOG_ENTRY_CONTRACT = {"name": "mcp_decision_log_entry", "version": "v1"}


@dataclass
class DecisionLog:
    """An append-only, hash-chained log of the decisions this server made.

    Each entry commits to the previous entry's hash, so a caller that
    fetched an earlier receipt can prove the log has not been rewritten
    underneath it. This mirrors ``actenon.anchors.local_log`` using the
    same canonicalisation and digest primitives, but stays in memory so
    demo mode needs no filesystem state.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)

    def append(self, *, kind: str, artifact: dict[str, Any]) -> dict[str, Any]:
        previous = self.entries[-1]["entry_hash"]["value"] if self.entries else None
        entry: dict[str, Any] = {
            "contract": dict(DECISION_LOG_ENTRY_CONTRACT),
            "index": len(self.entries),
            "kind": kind,
            "artifact": artifact,
            "previous_entry_hash": previous,
        }
        entry["entry_hash"] = {
            "algorithm": "sha-256",
            "canonicalization": CANONICALIZATION_PROFILE,
            "value": sha256_hex(entry),
        }
        self.entries.append(entry)
        return entry

    def find(self, artifact_id: str) -> dict[str, Any] | None:
        for entry in self.entries:
            artifact = entry["artifact"]
            if (
                artifact.get("receipt_id") == artifact_id
                or artifact.get("refusal_id") == artifact_id
            ):
                return entry
        return None

    def chain_reference(self, entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "index": entry["index"],
            "entry_hash": entry["entry_hash"],
            "previous_entry_hash": entry["previous_entry_hash"],
            "chain_length": len(self.entries),
        }


def _refusal_response(
    *,
    reason_code: str,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Every refusal answers both questions: what code, and why in English."""

    payload: dict[str, Any] = {
        "outcome": "REFUSED",
        "allowed": False,
        "reason_code": reason_code,
        "reason": reason,
    }
    payload.update(extra or {})
    return payload


def _coerce_proof(proof: Any) -> PCCB | None:
    if proof is None:
        return None
    if isinstance(proof, PCCB):
        return proof
    if isinstance(proof, str):
        # Strict parse: duplicate object keys, oversized, and over-deep
        # input are refused (ACTENON-JCS-STRICT-1 §4.12), not last-wins.
        # Note: over stdio the MCP SDK decodes the JSON-RPC envelope (and
        # pre-parses JSON-looking string arguments) before this runs.
        proof = loads_no_duplicate_keys(proof)
    return PCCB.from_dict(proof)


def _intent_refusal(exc: Exception, **extra: Any) -> dict[str, Any]:
    reason = exc.message if isinstance(exc, RefusalException) else str(exc)
    return _refusal_response(
        reason_code="INTENT_MALFORMED",
        reason=f"The supplied intent is not a valid Action Intent: {reason}",
        extra=extra,
    )


def _verifier_context(gate: ActenonGate, intent: ActionIntent) -> DynamicContextInput:
    """The same runtime context the gate builds for its own enforcement path."""

    selectors = intent.target.selectors or {"resource_id": intent.target.resource_id}
    constraints = intent.action.constraints or intent.action.parameters
    return DynamicContextInput(
        request_id=gate.request_id_factory(),
        audience=gate.audience,
        scope_capabilities=(intent.action.capability,),
        now=gate.clock(),
        facts={},
        parameter_constraints=dict(constraints),
        resource_selectors=(dict(selectors),),
    )


def build_server(*, demo: bool, gate: ActenonGate, signer: Any, audience: str) -> Any:
    """Construct the FastMCP server with the three (or four) tools bound."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise SystemExit(
            "actenon-mcp requires the 'mcp' extra: "
            "python -m pip install 'actenon-kernel[mcp]'"
        ) from exc

    server = FastMCP("actenon")
    log = DecisionLog()
    # Granular codes locally; the detailed-but-authenticated profile otherwise.
    # LOCAL_DEBUG is itself fail-closed in production-like environments.
    verifier = PCCBVerifier(
        signer,
        disclosure_mode=(
            VerifierDisclosureMode.LOCAL_DEBUG
            if demo
            else VerifierDisclosureMode.TRUSTED_DETAILED
        ),
    )

    def _banner(text: str) -> str:
        return f"{DEMO_BANNER}\n\n{text}" if demo else text

    def _build_intent(
        action_name: str,
        capability: str,
        parameters: dict[str, Any],
        target_type: str,
        target_id: str,
        intent: dict[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        """Use the caller's exact intent when given one, else build a fresh one.

        A proof is bound to one exact intent, including its id and time
        window. A caller retrying with a granted proof MUST pass back the
        intent that proof was issued for — building a lookalike here would
        produce a new intent_id and the proof would (correctly) be refused
        as INTENT_MISMATCH.
        """

        if intent is not None:
            payload = loads_no_duplicate_keys(intent) if isinstance(intent, str) else intent
            if not isinstance(payload, dict):
                raise ValueError("intent must be a JSON object")
            return dict(payload)
        return gate.build_action(
            action_name,
            capability,
            parameters,
            target_type=target_type,
            target_id=target_id,
        )

    @server.tool(
        name="actenon_verify",
        description=_banner(
            "Verify an Actenon proof (PCCB) against an exact action intent and "
            "return the typed outcome. This is pure verification: it performs no "
            "side effect, consumes no replay state, and emits no receipt. Use it "
            "to ask 'would this proof be accepted for this exact action?'. "
            "Returns outcome VALID or INVALID with a machine reason_code and a "
            "human-readable reason."
        ),
    )
    def actenon_verify(
        action_name: str,
        capability: str,
        parameters: dict[str, Any],
        target_type: str,
        target_id: str,
        proof: dict[str, Any] | str,
        intent: dict[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        try:
            intent_payload = _build_intent(
                action_name, capability, parameters, target_type, target_id, intent
            )
            parsed_intent = ActionIntentIntakeService().parse(intent_payload)
        except (RefusalException, ValueError, TypeError) as exc:
            return _intent_refusal(exc, valid=False)
        try:
            pccb = _coerce_proof(proof)
        # A model can hand us anything. Malformed proof must become a typed
        # refusal, never a crash — but only parse failures are caught, so a
        # genuine bug still surfaces instead of reading as "bad proof".
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            return _refusal_response(
                reason_code="PROOF_MALFORMED",
                reason=f"The supplied proof could not be parsed as a PCCB: {exc}",
                extra={"outcome": "INVALID", "valid": False},
            )
        if pccb is None:
            return _refusal_response(
                reason_code="PCCB_REQUIRED",
                reason="No proof was supplied. Actenon refuses by default: a "
                "consequential action needs a proof bound to that exact action.",
                extra={"outcome": "INVALID", "valid": False},
            )
        intent = parsed_intent
        context = _verifier_context(gate, intent)
        try:
            verifier.verify(intent, pccb, context)
        except RefusalException as exc:
            return _refusal_response(
                reason_code=exc.refusal_code,
                reason=exc.message,
                extra={
                    "outcome": "INVALID",
                    "valid": False,
                    "intent_id": intent.intent_id,
                },
            )
        return {
            "outcome": "VALID",
            "valid": True,
            "reason_code": None,
            "reason": "The proof is bound to this exact action, target, audience, "
            "and time window, and its signature verified.",
            "intent_id": intent.intent_id,
            "pccb_id": pccb.pccb_id,
        }

    @server.tool(
        name="actenon_gate",
        description=_banner(
            "Evaluate an action intent at the execution edge and return ALLOW or a "
            "typed refusal. This is the enforcement path: it verifies the proof, "
            "consumes single-use replay state, and emits a hash-chained Receipt "
            "(on allow) or Refusal (on deny) retrievable via actenon_receipt. "
            "Call it WITHOUT a proof to see the default-deny behaviour and the "
            "exact reason. When retrying with a proof, pass back the `intent` it "
            "was issued for — a proof is bound to one exact intent. The proof "
            "must come from your trusted host or authority broker; a model must "
            "never mint its own authority."
        ),
    )
    def actenon_gate(
        action_name: str,
        capability: str,
        parameters: dict[str, Any],
        target_type: str,
        target_id: str,
        proof: dict[str, Any] | str | None = None,
        intent: dict[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        try:
            intent_payload = _build_intent(
                action_name, capability, parameters, target_type, target_id, intent
            )
            parsed_intent = ActionIntentIntakeService().parse(intent_payload)
        except (RefusalException, ValueError, TypeError) as exc:
            return _intent_refusal(exc)
        try:
            pccb = _coerce_proof(proof)
        # A model can hand us anything. Malformed proof must become a typed
        # refusal, never a crash — but only parse failures are caught, so a
        # genuine bug still surfaces instead of reading as "bad proof".
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            return _refusal_response(
                reason_code="PROOF_MALFORMED",
                reason=f"The supplied proof could not be parsed as a PCCB: {exc}",
            )

        outcome = gate.protect(
            parsed_intent,
            proof=pccb,
            side_effect=lambda **kwargs: {
                "simulated": True,
                "note": "actenon-mcp does not perform your side effect; it decides "
                "whether your side effect is allowed to run.",
            },
        )

        if outcome.refusal is not None:
            artifact = outcome.refusal.to_dict()
            entry = log.append(kind="refusal", artifact=artifact)
            return _refusal_response(
                reason_code=artifact["reason_code"],
                reason=artifact["message"],
                extra={
                    "refusal_id": artifact["refusal_id"],
                    "retryable": artifact.get("retryable", False),
                    "intent_id": artifact.get("intent_id"),
                    "chain": log.chain_reference(entry),
                    "next_step": "Obtain a proof scoped to this exact action from "
                    "your authority broker, then call actenon_gate again.",
                },
            )

        artifact = outcome.receipt.to_dict()
        entry = log.append(kind="receipt", artifact=artifact)
        return {
            "outcome": "ALLOW",
            "allowed": True,
            "reason_code": None,
            "reason": "The proof verified for this exact action, target, audience, "
            "scope, and time window, and single-use replay state was consumed.",
            "receipt_id": artifact["receipt_id"],
            "intent_id": artifact.get("intent_id"),
            "chain": log.chain_reference(entry),
        }

    @server.tool(
        name="actenon_receipt",
        description=_banner(
            "Return the hash-chained Receipt or Refusal artifact for a prior "
            "decision made by this server, addressed by receipt_id or refusal_id. "
            "Each log entry commits to the previous entry's hash, so a caller can "
            "detect a rewritten history. Call with no id to list the chain."
        ),
    )
    def actenon_receipt(artifact_id: str | None = None) -> dict[str, Any]:
        if artifact_id is None:
            return {
                "outcome": "OK",
                "reason_code": None,
                "reason": f"This server has recorded {len(log.entries)} decision(s).",
                "chain_length": len(log.entries),
                "entries": [
                    {
                        "index": entry["index"],
                        "kind": entry["kind"],
                        "artifact_id": entry["artifact"].get("receipt_id")
                        or entry["artifact"].get("refusal_id"),
                        "entry_hash": entry["entry_hash"]["value"],
                        "previous_entry_hash": entry["previous_entry_hash"],
                    }
                    for entry in log.entries
                ],
            }
        entry = log.find(artifact_id)
        if entry is None:
            return _refusal_response(
                reason_code="ARTIFACT_NOT_FOUND",
                reason=f"No decision with id {artifact_id!r} was recorded by this "
                "server. Receipts live for the lifetime of the process; a "
                "restarted demo server starts an empty chain.",
                extra={"outcome": "NOT_FOUND"},
            )
        return {
            "outcome": "OK",
            "reason_code": None,
            "reason": f"Decision {artifact_id} is entry {entry['index']} in this "
            "server's hash-chained decision log.",
            "kind": entry["kind"],
            "artifact": entry["artifact"],
            "chain": log.chain_reference(entry),
        }

    if demo:

        @server.tool(
            name="actenon_demo_grant",
            description=(
                f"{DEMO_BANNER}\n\n"
                "Issue a proof scoped to one exact action. This tool exists ONLY in "
                "demo mode and is ABSENT from a production server: in a real "
                "deployment the grant comes from your authority broker "
                "(actenon-permit) after human approval, and the verifier never "
                "issues its own authority. It is here so a single connected client "
                "can walk the full refuse → grant → retry → receipt loop offline."
            ),
        )
        def actenon_demo_grant(
            action_name: str,
            capability: str,
            parameters: dict[str, Any],
            target_type: str,
            target_id: str,
        ) -> dict[str, Any]:
            intent_payload = _build_intent(
                action_name, capability, parameters, target_type, target_id
            )
            pccb = gate.mint_proof(intent_payload)
            return {
                "outcome": "GRANTED",
                "intent": intent_payload,
                "reason_code": None,
                "reason": DEMO_BANNER
                + " A scoped, single-use proof was issued for this exact action. "
                "It will not verify for any other action, target, parameter set, "
                "or audience. Pass BOTH `proof` and `intent` back to actenon_gate: "
                "the proof is bound to this exact intent, so a rebuilt lookalike "
                "intent is refused as INTENT_MISMATCH.",
                "proof": pccb.to_dict(),
                "pccb_id": pccb.pccb_id,
                "expires_at": pccb.expires_at.isoformat()
                if hasattr(pccb.expires_at, "isoformat")
                else pccb.expires_at,
            }

    return server


def build_demo_gate(audience: str = DEFAULT_AUDIENCE) -> tuple[ActenonGate, Any]:
    """A gate with an ephemeral key and in-memory state. No config, no network."""

    # A fresh random secret per process: the demo never signs with the public
    # default development secret, and nothing it mints survives a restart.
    signer = build_local_proof_signer(token_bytes(32))
    gate = ActenonGate(
        verifier=signer,
        signer=signer,
        audience=audience,
        issuer="service:actenon-mcp-demo",
    )
    return gate, signer


def build_configured_gate(*, key_file: Path, audience: str) -> tuple[ActenonGate, Any]:
    """Load signing material for a non-demo server. Secrets are never logged."""

    if not key_file.exists():
        raise SystemExit(
            f"actenon-mcp: signing key file not found: {key_file}\n"
            "Non-demo mode requires signing material and fails closed without it.\n"
            "Run `actenon-mcp --demo` for an offline demo server with an "
            "ephemeral key."
        )
    secret = key_file.read_bytes().strip()
    if not secret:
        raise SystemExit(
            f"actenon-mcp: signing key file is empty: {key_file}\n"
            "Refusing to start rather than fall back to a development key."
        )
    validate_signing_backend_for_environment("development_local_hmac")
    signer = build_local_proof_signer(secret)
    gate = ActenonGate(
        verifier=signer,
        signer=signer,
        audience=audience,
        issuer="service:actenon-mcp",
    )
    return gate, signer


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="actenon-mcp",
        description="Actenon MCP server — proof verification at the tool boundary.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run offline with an ephemeral key and in-memory state. "
        "No configuration, no network, no keys on disk. Not for production.",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Path to signing material for a non-demo server. Required unless "
        "--demo is set. The file's contents are never logged.",
    )
    parser.add_argument(
        "--audience",
        default=DEFAULT_AUDIENCE,
        help=f"Audience this server verifies for (default: {DEFAULT_AUDIENCE}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # stdout is the MCP transport. Everything human-facing goes to stderr.
    if args.demo:
        # Refuse on either definition of "production-like": the signing
        # guard's (ACTENON_ENV=prod/production/staging/..., production
        # flags) or the verifier's, which only permits local/dev/test/demo.
        if (
            is_production_like_environment()
            or default_disclosure_mode() is not VerifierDisclosureMode.LOCAL_DEBUG
        ):
            raise SystemExit(
                "actenon-mcp: --demo refused in a production-like environment "
                "(ACTENON_ENV is not local/dev/test/demo, or an Actenon production "
                "flag is set). The demo signs with an ephemeral development key "
                "and must never run in production."
            )
        try:
            gate, signer = build_demo_gate(args.audience)
        except ProductionSigningGuardError as exc:
            raise SystemExit(f"actenon-mcp: {exc}") from exc
        print(f"actenon-mcp: {DEMO_BANNER}", file=sys.stderr)
        print(
            "actenon-mcp: ephemeral in-process key, in-memory replay store, "
            "no network calls, no configuration read.",
            file=sys.stderr,
        )
        print(
            "actenon-mcp: proofs minted here verify nowhere else and do not "
            "survive a restart.",
            file=sys.stderr,
        )
    else:
        if args.key_file is None:
            raise SystemExit(
                "actenon-mcp: no signing material configured.\n"
                "Non-demo mode fails closed: pass --key-file PATH, or run\n"
                "  actenon-mcp --demo\n"
                "for an offline demo server with an ephemeral key."
            )
        try:
            gate, signer = build_configured_gate(
                key_file=args.key_file, audience=args.audience
            )
        except ProductionSigningGuardError as exc:
            raise SystemExit(f"actenon-mcp: {exc}") from exc
        print(
            f"actenon-mcp: verifying for audience {args.audience}.",
            file=sys.stderr,
        )

    server = build_server(
        demo=args.demo, gate=gate, signer=signer, audience=args.audience
    )
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
