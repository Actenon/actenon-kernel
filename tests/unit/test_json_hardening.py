from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from actenon.cli import _load_json
from actenon.core.errors import ProofVerificationError
from actenon.core.json import (
    DEFAULT_MAX_JSON_BYTES,
    DEFAULT_MAX_JSON_DEPTH,
    DuplicateJSONKeyError,
    JSONInputTooLargeError,
    JSONNestingDepthError,
    loads_no_duplicate_keys,
)
from actenon.evidence import JsonArtifactPCCBStore
from actenon.models import (
    ActionHashSpec,
    ActionIntent,
    ActionSpec,
    AudienceRef,
    DynamicContextInput,
    PCCB,
    PartyRef,
    ScopeSpec,
    SignatureSpec,
    TargetRef,
    TenantRef,
)
from actenon.proof import PCCBVerifier, VerifierDisclosureMode, VerifierDisclosureMode, build_local_proof_signer, canonicalize_bytes
from actenon.proof.canonical import DEFAULT_MAX_CANONICAL_OUTPUT_BYTES
from actenon.receipts import JsonArtifactReceiptStore, JsonArtifactRefusalStore


def _deep_value() -> object:
    value: object = "leaf"
    for _ in range(DEFAULT_MAX_JSON_DEPTH):
        value = [value]
    return value


class JsonHardeningTests(unittest.TestCase):
    def test_duplicate_json_key_is_rejected_in_nested_object(self) -> None:
        with self.assertRaises(DuplicateJSONKeyError):
            loads_no_duplicate_keys('{"outer":{"token":"one","token":"two"}}')

    def test_normal_json_still_parses(self) -> None:
        payload = loads_no_duplicate_keys('{"outer":{"token":"one"},"items":[1,true,null]}')

        self.assertEqual({"outer": {"token": "one"}, "items": [1, True, None]}, payload)

    def test_cli_artifact_load_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            target = Path(tempdir) / "pccb.json"
            target.write_text('{"contract":{"name":"pccb","name":"shadow"}}', encoding="utf-8")

            with self.assertRaises(DuplicateJSONKeyError):
                _load_json(str(target))

    def test_pccb_artifact_store_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            target = Path(tempdir) / "case" / "pccb.json"
            target.parent.mkdir(parents=True)
            target.write_text('{"pccb_id":"pccb_001","pccb_id":"shadow"}', encoding="utf-8")

            with self.assertRaises(DuplicateJSONKeyError):
                JsonArtifactPCCBStore(Path(tempdir)).list_pccbs()

    def test_receipt_and_refusal_artifact_stores_reject_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            receipts = root / "receipts"
            refusals = root / "refusals"
            receipts.mkdir()
            refusals.mkdir()
            (receipts / "rcpt_001.json").write_text(
                '{"receipt_id":"rcpt_001","receipt_id":"shadow"}',
                encoding="utf-8",
            )
            (refusals / "rfsl_001.json").write_text(
                '{"refusal_id":"rfsl_001","refusal_id":"shadow"}',
                encoding="utf-8",
            )

            with self.assertRaises(DuplicateJSONKeyError):
                JsonArtifactReceiptStore(root).get_receipt("rcpt_001")
            with self.assertRaises(DuplicateJSONKeyError):
                JsonArtifactRefusalStore(root).get_refusal("rfsl_001")

    def test_deeply_nested_json_parse_is_rejected(self) -> None:
        raw = "[" * (DEFAULT_MAX_JSON_DEPTH + 1) + "0" + "]" * (DEFAULT_MAX_JSON_DEPTH + 1)

        with self.assertRaises(JSONNestingDepthError):
            loads_no_duplicate_keys(raw)

    def test_pathological_parser_recursion_is_rejected_as_depth_error(self) -> None:
        raw = "[" * 2000 + "0" + "]" * 2000

        with self.assertRaises(JSONNestingDepthError):
            loads_no_duplicate_keys(raw, max_bytes=len(raw) + 1)

    def test_large_json_input_is_rejected(self) -> None:
        raw = '{"payload":"' + ("a" * DEFAULT_MAX_JSON_BYTES) + '"}'

        with self.assertRaises(JSONInputTooLargeError):
            loads_no_duplicate_keys(raw)

    def test_canonicalizer_rejects_deeply_nested_input(self) -> None:
        with self.assertRaises(JSONNestingDepthError):
            canonicalize_bytes({"deep": _deep_value()})

    def test_canonicalizer_rejects_oversize_output(self) -> None:
        with self.assertRaises(JSONInputTooLargeError):
            canonicalize_bytes({"payload": "a" * DEFAULT_MAX_CANONICAL_OUTPUT_BYTES})

    def test_proof_verifier_fails_closed_on_pathological_action_hash_input(self) -> None:
        now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        action = ActionSpec(
            name="demo.deep",
            capability="demo.deep",
            parameters={"deep": _deep_value()},
        )
        target = TargetRef(resource_type="demo", resource_id="deep")
        tenant = TenantRef(tenant_id="tenant_demo")
        requester = PartyRef(type="service", id="agent")
        intent = ActionIntent(
            intent_id="intent_deep",
            issued_at=now,
            expires_at=now,
            tenant=tenant,
            requester=requester,
            action=action,
            target=target,
        )
        pccb = PCCB(
            pccb_id="pccb_deep",
            intent_id=intent.intent_id,
            issued_at=now,
            not_before=now,
            expires_at=now,
            issuer=PartyRef(type="service", id="issuer"),
            subject=requester,
            tenant=tenant,
            audience=AudienceRef(type="service", id="endpoint"),
            action=action,
            target=target,
            scope=ScopeSpec(mode="exact", capabilities=("demo.deep",), single_use=True),
            nonce="nonce_deep",
            action_hash=ActionHashSpec(
                algorithm="sha-256",
                canonicalization="RFC8785-JCS",
                value="not-computed",
            ),
            signature=SignatureSpec(
                algorithm="HS256",
                key_id="local-proof-v1",
                encoding="base64url",
                value="not-used",
            ),
        )
        context = DynamicContextInput(
            request_id="req_deep",
            audience=AudienceRef(type="service", id="endpoint"),
            scope_capabilities=("demo.deep",),
            now=now,
        )

        with self.assertRaisesRegex(ProofVerificationError, "PROOF_PAYLOAD_INVALID"):
            PCCBVerifier(build_local_proof_signer(), disclosure_mode=VerifierDisclosureMode.LOCAL_DEBUG).verify(intent, pccb, context)


if __name__ == "__main__":
    unittest.main()
