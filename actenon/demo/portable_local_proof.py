from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from actenon.api.intake import ActionIntentIntakeService
from actenon.models import AudienceRef, DynamicContextInput, PartyRef, PolicyDecision
from actenon.proof import PCCBMinter, build_local_proof_signer
from actenon.verifier import VerifierSDK
from examples.hello_world_protected_resource_python.protected_resource import HelloWorldProtectedResource


FIXED_BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
FIXED_EXPIRES_AT = FIXED_BASE_TIME + timedelta(minutes=5)


def build_hello_world_action_intent_payload() -> dict[str, Any]:
    return {
        "contract": {"name": "action_intent", "version": "v1"},
        "intent_id": "intent_portable_hello_world_001",
        "issued_at": FIXED_BASE_TIME.isoformat().replace("+00:00", "Z"),
        "expires_at": FIXED_EXPIRES_AT.isoformat().replace("+00:00", "Z"),
        "tenant": {"tenant_id": "tenant_portable_demo"},
        "requester": {"type": "service", "id": "portable_demo_actor", "display_name": "Portable Demo Actor"},
        "action": {
            "name": "hello_world.read",
            "capability": "protected_resource.read",
            "parameters": {"message": "portable hello world"},
            "constraints": {"exact_message": "portable hello world"},
            "scope": {"target_resource_type": "hello_resource", "single_use": True},
        },
        "target": {"resource_type": "hello_resource", "resource_id": "hello_resource_demo_001"},
        "metadata": {"distribution": "portable-open-layer"},
        "context": {"demo": "portable_local_proof"},
    }


def _write_json(target: Path, payload: Any) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_portable_local_proof_demo(artifact_root: Path) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)

    payload = build_hello_world_action_intent_payload()
    intake = ActionIntentIntakeService()
    intent = intake.parse(payload)
    audience = AudienceRef(type="service", id="portable-hello-world-endpoint")
    context = DynamicContextInput(
        request_id="req_portable_hello_world_001",
        audience=audience,
        scope_capabilities=("protected_resource.read",),
        now=FIXED_BASE_TIME,
        parameter_constraints={"exact_message": "portable hello world"},
        resource_selectors=({"resource_id": "hello_resource_demo_001"},),
    )
    decision = PolicyDecision(
        outcome="allow",
        summary="Portable local proof mode allows the hello-world protected resource example.",
        rule_evaluations=(),
        reason_codes=("LOCAL_PROOF_ALLOW",),
    )

    signer = build_local_proof_signer()
    minter = PCCBMinter(
        signer=signer,
        issuer=PartyRef(type="service", id="portable_local_issuer", display_name="Portable Local Issuer"),
        pccb_id_factory=lambda: "pccb_portable_hello_world_001",
        nonce_factory=lambda: "nonce-portable-hello-world-00000001",
    )
    pccb = minter.mint(intent, decision, context)

    sdk = VerifierSDK(signer)
    verified_request = sdk.verify(intent=intent, pccb=pccb, context=context)
    resource = HelloWorldProtectedResource()
    response = resource.handle(verified_request)

    _write_json(artifact_root / "action_intent.json", payload)
    _write_json(artifact_root / "pccb.json", pccb.to_dict())
    _write_json(
        artifact_root / "verification_result.json",
        {
            "request_id": verified_request.context.request_id,
            "audience": verified_request.context.audience.to_dict(),
            "scope_capabilities": list(verified_request.context.scope_capabilities),
            "action_hash": verified_request.pccb.action_hash.to_dict(),
        },
    )
    _write_json(artifact_root / "protected_resource_response.json", response)

    manifest = {
        "artifact_root": str(artifact_root),
        "action_intent": str(artifact_root / "action_intent.json"),
        "pccb": str(artifact_root / "pccb.json"),
        "verification_result": str(artifact_root / "verification_result.json"),
        "protected_resource_response": str(artifact_root / "protected_resource_response.json"),
    }
    _write_json(artifact_root / "manifest.json", manifest)
    (artifact_root / "SUMMARY.txt").write_text(
        "\n".join(
            [
                "Portable local proof mode completed successfully.",
                f"Artifact root: {artifact_root}",
                "Protected resource result: success",
                f"Intent id: {intent.intent_id}",
                f"PCCB id: {pccb.pccb_id}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the portable hello-world local proof demo.")
    parser.add_argument(
        "--artifacts-dir",
        default=str(Path.cwd() / "artifacts" / "portable_local_proof"),
        help="Directory where portable local proof artifacts should be written.",
    )
    args = parser.parse_args()
    manifest = run_portable_local_proof_demo(Path(args.artifacts_dir))
    print("Portable local proof mode completed.")
    print(f"Artifacts: {manifest['artifact_root']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
