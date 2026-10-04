"""Python kernel runner. argv: corpus_dir out.jsonl label

Uses only the installed actenon-kernel (asserts it is not a source tree):
raw bytes -> actenon.core.json.loads_no_duplicate_keys -> VerifierSDK.verify
(LOCAL_DEBUG disclosure, for granular refusal codes). Ed25519 is verified
through the kernel's well-known-key path (_verify_signature_with_resolved_key).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("ACTENON_ENV", "test")

import actenon  # noqa: E402
from actenon.core.json import loads_no_duplicate_keys  # noqa: E402
from actenon.models import AudienceRef, PartyRef  # noqa: E402
from actenon.models.contracts import parse_timestamp  # noqa: E402
from actenon.proof import VerifierDisclosureMode  # noqa: E402
from actenon.proof.signers.local import HmacSha256Signer  # noqa: E402
from actenon.proof.signers.well_known import (  # noqa: E402
    DiscoveredVerificationKey,
    ResolvedVerificationKey,
    _verify_signature_with_resolved_key,
)
from actenon.verifier import VerifierSDK  # noqa: E402

corpus, out_path, label = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
if os.environ.get("DIFF_ALLOW_SOURCE_TREE") != "1":
    assert "site-packages" in actenon.__file__, f"not an installed package: {actenon.__file__}"
trust = json.loads((corpus / "trust.json").read_text())


class KernelJwkVerifier:
    def __init__(self, jwk: dict) -> None:
        self.key_id = jwk["kid"]
        self.algorithm = "EdDSA"
        self._resolved = ResolvedVerificationKey(
            issuer=PartyRef(type="service", id="issuer_diff"),
            origin="diff:corpus",
            published_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            key=DiscoveredVerificationKey(key_id=self.key_id, algorithm="EdDSA", use=("proof_issuance",), status="active", public_key_jwk=dict(jwk)),
        )

    def verify(self, payload: bytes, signature) -> bool:
        if signature.key_id != self.key_id or signature.algorithm != self.algorithm:
            return False
        try:
            return _verify_signature_with_resolved_key(payload=payload, signature=signature, resolved_key=self._resolved)
        except Exception:
            return False


hmac = HmacSha256Signer(secret=trust["hmac"]["secret_utf8"].encode(), key_id=trust["hmac"]["key_id"])
jwk = {k: v for k, v in trust["ed25519"].items()}
ed = KernelJwkVerifier(jwk)

manifest = json.loads((corpus / "manifest.json").read_text())
with out_path.open("w") as out:
    for case in manifest["cases"]:
        d = corpus / case["id"]
        ctx = json.loads((d / "context.json").read_text())
        sdk = VerifierSDK(
            ed if case["alg"] == "EdDSA" else hmac,
            clock_skew_tolerance=timedelta(milliseconds=ctx.get("clock_skew_ms", 0)),
            disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG,
        )
        try:
            intent = loads_no_duplicate_keys((d / "intent.json").read_bytes())
            pccb = loads_no_duplicate_keys((d / "pccb.json").read_bytes())
            context = sdk.build_context(
                request_id=ctx["request_id"],
                audience=AudienceRef.from_dict(ctx["audience"], "context.audience"),
                now=parse_timestamp(ctx["now"], "context.now"),
                scope_capabilities=tuple(ctx["scope_capabilities"]),
                parameter_constraints=dict(ctx["parameter_constraints"]),
                resource_selectors=tuple(ctx["resource_selectors"]),
            )
            sdk.verify(intent=intent, pccb=pccb, context=context)
            row = {"id": case["id"], "outcome": "ACCEPT", "code": None}
        except Exception as exc:  # every failure is a refusal; record its code
            code = getattr(exc, "refusal_code", None) or type(exc).__name__
            row = {"id": case["id"], "outcome": "REFUSE", "code": code}
        out.write(json.dumps(row) + "\n")
print(f"{label}: {len(manifest['cases'])} cases -> {out_path} (kernel {actenon.__file__})")
