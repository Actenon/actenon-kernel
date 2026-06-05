"""
Hello Protected Endpoint

A deliberately tiny Actenon-style protected endpoint example.

This is not a production implementation. It is a small, readable example that
shows the core boundary:

    verify proof before side effect

Run:

    python3 examples/hello_protected_endpoint/server.py
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason_code: str | None
    side_effect_executed: bool
    artifact: dict[str, Any]


def canonical_action_hash(action: dict[str, Any]) -> str:
    """
    Tiny deterministic action hash for the example.

    Real Actenon paths use the kernel's canonical proof and verification
    semantics. This example keeps the mechanics visible.
    """
    material = repr(sorted(action.items())).encode("utf-8")
    return sha256(material).hexdigest()


def protected_endpoint(action: dict[str, Any], proof: dict[str, Any] | None) -> Decision:
    """
    The protected endpoint is the enforcement boundary.

    It refuses before the side effect when proof is missing or action-mismatched.
    """
    expected_action_hash = canonical_action_hash(action)

    if proof is None:
        return Decision(
            outcome="refused",
            reason_code="MISSING_PROOF",
            side_effect_executed=False,
            artifact={
                "type": "refusal",
                "reason_code": "MISSING_PROOF",
                "side_effect_executed": False,
            },
        )

    if proof.get("action_hash") != expected_action_hash:
        return Decision(
            outcome="refused",
            reason_code="ACTION_HASH_MISMATCH",
            side_effect_executed=False,
            artifact={
                "type": "refusal",
                "reason_code": "ACTION_HASH_MISMATCH",
                "side_effect_executed": False,
            },
        )

    # Side effect would happen here, after proof verification.
    return Decision(
        outcome="executed",
        reason_code=None,
        side_effect_executed=True,
        artifact={
            "type": "receipt",
            "outcome": "executed",
            "side_effect_executed": True,
            "action_hash": expected_action_hash,
        },
    )


def main() -> None:
    action = {
        "type": "database.delete",
        "resource": "customers",
        "parameters": {"customer_id": "customer_123"},
    }

    print("UNPROVEN REQUEST")
    refused = protected_endpoint(action=action, proof=None)
    print(f"decision: {refused.outcome}")
    print(f"reason_code: {refused.reason_code}")
    print(f"side_effect_executed: {refused.side_effect_executed}")
    print(f"artifact: {refused.artifact}")
    print()

    print("VALID REQUEST")
    valid_proof = {"action_hash": canonical_action_hash(action)}
    executed = protected_endpoint(action=action, proof=valid_proof)
    print(f"decision: {executed.outcome}")
    print(f"reason_code: {executed.reason_code}")
    print(f"side_effect_executed: {executed.side_effect_executed}")
    print(f"artifact: {executed.artifact}")


if __name__ == "__main__":
    main()
