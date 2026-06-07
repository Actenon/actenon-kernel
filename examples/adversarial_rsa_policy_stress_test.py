import argparse
import json
import random
import time
import uuid
from typing import Any, Dict, List, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class ActionPayload:
    """
    Deterministic payload containing domain-specific action data.

    This is a standalone evidence harness. It demonstrates the same core
    Actenon boundary invariant with raw RSA primitives:

        approved exact action -> executes
        replay / tamper / stale / future / policy-denied action -> refused
    """

    def __init__(
        self,
        domain: str,
        action: str,
        target_id: str,
        parameters: Dict[str, Any],
        nonce: str = None,
        timestamp: float = None,
    ):
        self.domain = domain
        self.action = action
        self.target_id = target_id
        self.parameters = parameters
        self.nonce = nonce or str(uuid.uuid4())
        self.timestamp = timestamp or time.time()

    def serialize(self) -> bytes:
        data = {
            "domain": self.domain,
            "action": self.action,
            "target_id": self.target_id,
            "parameters": self.parameters,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ProofMinter:
    """
    Central policy issuer.

    The issuer decides whether an action should receive proof.
    The execution gate later verifies that proof immediately before side effect.
    """

    def __init__(self, private_key: rsa.RSAPrivateKey):
        self.private_key = private_key
        self.policies = {
            "devops": {
                "blocked_targets": ["db-prod-01", "k8s-core-cluster"],
                "allowed_actions": [
                    "restart_service",
                    "scale_deployment",
                    "terminate_instance",
                ],
            },
            "iam": {
                "max_role_level": 3,
                "allowed_actions": ["grant_role", "revoke_role"],
            },
            "crm": {
                "max_bulk_delete_limit": 50,
                "allowed_actions": ["bulk_delete", "update_contact"],
            },
        }

    def mint_proof(self, payload: ActionPayload) -> bytes:
        domain = payload.domain
        action = payload.action
        target = payload.target_id
        params = payload.parameters

        if domain not in self.policies:
            raise PermissionError(f"Minter Policy: Unknown domain '{domain}'")

        policy = self.policies[domain]

        if action not in policy.get("allowed_actions", []):
            raise PermissionError(f"Minter Policy: Action '{action}' not allowed.")

        if domain == "devops":
            if target in policy["blocked_targets"]:
                raise PermissionError(
                    f"Minter Policy: Target '{target}' is blacklisted."
                )

        elif domain == "iam":
            if action == "grant_role" and params.get("role_level", 0) > policy["max_role_level"]:
                raise PermissionError(
                    f"Minter Policy: Role level {params.get('role_level')} exceeds limit of {policy['max_role_level']}."
                )

        elif domain == "crm":
            if action == "bulk_delete" and params.get("count", 0) > policy["max_bulk_delete_limit"]:
                raise PermissionError(
                    f"Minter Policy: Bulk delete of {params.get('count')} exceeds safety ceiling."
                )

        return self.private_key.sign(
            payload.serialize(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )


class ExecutionGate:
    """
    Deterministic verification gate.

    It refuses before side effect if the proof is replayed, expired, future-dated,
    missing, spoofed, or bound to different payload bytes.
    """

    def __init__(self, public_key: rsa.RSAPublicKey, ttl_seconds: float = 300.0):
        self.public_key = public_key
        self.ttl_seconds = ttl_seconds
        self.used_nonces: Set[str] = set()

    def verify_and_authorize(self, payload: ActionPayload, signature: bytes) -> bool:
        if payload.nonce in self.used_nonces:
            raise ValueError("Execution Gate: Replay attack detected. Nonce already consumed.")

        current_time = time.time()

        if current_time - payload.timestamp > self.ttl_seconds:
            raise TimeoutError("Execution Gate: Attestation expired.")

        if payload.timestamp > current_time + 5.0:
            raise ValueError("Execution Gate: Future timestamp detected.")

        try:
            self.public_key.verify(
                signature,
                payload.serialize(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise ValueError(
                "Execution Gate: CRYPTOGRAPHIC VERIFICATION FAILED. Payload altered or signature spoofed."
            ) from exc

        self.used_nonces.add(payload.nonce)
        return True


def _sign_raw(private_key: rsa.RSAPrivateKey, payload: ActionPayload) -> bytes:
    return private_key.sign(
        payload.serialize(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def run_adversarial_stress_test(runs: int = 1000, seed: int = 1337) -> Dict[str, int]:
    rng = random.Random(seed)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    minter = ProofMinter(private_key)
    gate = ExecutionGate(public_key, ttl_seconds=300.0)

    stats = {
        "valid_executed": 0,
        "valid_failed_erroneously": 0,
        "blocked_replay": 0,
        "blocked_tampered_payload": 0,
        "blocked_expired_ttl": 0,
        "blocked_future_timestamp": 0,
        "blocked_minter_guardrail": 0,
        "undetected_attacks": 0,
    }

    consumed_signatures: List[Tuple[ActionPayload, bytes]] = []

    for _ in range(50):
        valid_payload = ActionPayload(
            "devops",
            "restart_service",
            "web-srv-01",
            {"force": True},
        )
        sig = minter.mint_proof(valid_payload)
        gate.verify_and_authorize(valid_payload, sig)
        consumed_signatures.append((valid_payload, sig))

    attack_types = [
        "legitimate",
        "replay",
        "tamper_amount",
        "tamper_target",
        "expired_ttl",
        "future_timestamp",
        "minter_bypass_devops",
        "minter_bypass_iam",
        "minter_bypass_crm",
    ]

    for i in range(runs):
        attack_type = attack_types[i % len(attack_types)]

        try:
            if attack_type == "legitimate":
                payload = ActionPayload(
                    domain=rng.choice(["devops", "iam", "crm"]),
                    action=rng.choice(["restart_service", "revoke_role", "update_contact"]),
                    target_id="resource-abc",
                    parameters={"role_level": 1, "count": 10},
                )
                sig = minter.mint_proof(payload)
                gate.verify_and_authorize(payload, sig)
                stats["valid_executed"] += 1

            elif attack_type == "replay":
                old_payload, old_sig = rng.choice(consumed_signatures)
                gate.verify_and_authorize(old_payload, old_sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "tamper_amount":
                payload = ActionPayload("crm", "update_contact", "contact-1", {"value": "normal"})
                sig = minter.mint_proof(payload)
                payload.parameters = {"value": "tampered_value", "count": 999999}
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "tamper_target":
                payload = ActionPayload("devops", "restart_service", "web-srv-02", {})
                sig = minter.mint_proof(payload)
                payload.target_id = "db-prod-01"
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "expired_ttl":
                payload = ActionPayload(
                    "devops",
                    "restart_service",
                    "web-srv-01",
                    {},
                    timestamp=time.time() - 3600.0,
                )
                sig = _sign_raw(private_key, payload)
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "future_timestamp":
                payload = ActionPayload(
                    "devops",
                    "restart_service",
                    "web-srv-01",
                    {},
                    timestamp=time.time() + 3600.0,
                )
                sig = _sign_raw(private_key, payload)
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "minter_bypass_devops":
                payload = ActionPayload("devops", "terminate_instance", "db-prod-01", {})
                sig = minter.mint_proof(payload)
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "minter_bypass_iam":
                payload = ActionPayload("iam", "grant_role", "eve", {"role_level": 4})
                sig = minter.mint_proof(payload)
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

            elif attack_type == "minter_bypass_crm":
                payload = ActionPayload("crm", "bulk_delete", "users_table", {"count": 1000})
                sig = minter.mint_proof(payload)
                gate.verify_and_authorize(payload, sig)
                stats["undetected_attacks"] += 1

        except PermissionError:
            stats["blocked_minter_guardrail"] += 1
        except TimeoutError:
            stats["blocked_expired_ttl"] += 1
        except ValueError as exc:
            message = str(exc)
            if "Replay" in message:
                stats["blocked_replay"] += 1
            elif "Future" in message:
                stats["blocked_future_timestamp"] += 1
            elif "CRYPTOGRAPHIC VERIFICATION FAILED" in message:
                stats["blocked_tampered_payload"] += 1
            else:
                stats["valid_failed_erroneously"] += 1
        except Exception:
            stats["valid_failed_erroneously"] += 1

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Standalone adversarial RSA proof-gate stress evidence."
    )
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    print(f"Beginning adversarial proof-gate stress test: runs={args.runs}, seed={args.seed}")
    results = run_adversarial_stress_test(args.runs, args.seed)
    print(json.dumps(results, indent=4, sort_keys=True))

    if results["undetected_attacks"] == 0:
        print("PASS: no adversarial attack reached execution.")
    else:
        print("FAIL: at least one adversarial attack reached execution.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
