from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from actenon.core.errors import ProofVerificationError
from actenon.models import ActionIntent, DynamicContextInput, PCCB, PartyRef
from actenon.proof import PCCBVerifier, WellKnownKeyResolver, WellKnownKeySignatureVerifier
from actenon.receipts import OutcomeAttestationService, OutcomeAttestationVerificationError

try:
    import cryptography  # noqa: F401
except Exception:  # pragma: no cover - exercised only in core-only installs
    cryptography = None


VECTOR_DIR = (
    Path(__file__).resolve().parents[2]
    / "conformance"
    / "vectors"
    / "cloud_invoice_payment_v1"
)


def _load_json(relative_path: str) -> dict[str, object]:
    return json.loads((VECTOR_DIR / relative_path).read_text(encoding="utf-8"))


def _fetcher(document: dict[str, object]):
    def fetch_document(url: str, timeout_seconds: float) -> tuple[dict[str, str], bytes]:
        assert url == "https://actenon-cloud.local/.well-known/actenon/keys.json"
        assert timeout_seconds > 0
        return {"cache-control": "max-age=300"}, json.dumps(document).encode("utf-8")

    return fetch_document


def _verifier(issuer_keys: dict[str, object]) -> PCCBVerifier:
    resolver = WellKnownKeyResolver(
        issuer_origin="https://actenon-cloud.local",
        fetch_document=_fetcher(issuer_keys),
    )
    return PCCBVerifier(WellKnownKeySignatureVerifier(resolver=resolver))


def _outcome_attestation_verifier(issuer_keys: dict[str, object]) -> WellKnownKeySignatureVerifier:
    resolver = WellKnownKeyResolver(
        issuer_origin="https://actenon-cloud.local",
        fetch_document=_fetcher(issuer_keys),
    )
    return WellKnownKeySignatureVerifier(
        resolver=resolver,
        required_use="outcome_attestation",
    )


def _outcome_attestation_service(
    issuer_keys: dict[str, object],
) -> tuple[OutcomeAttestationService, WellKnownKeySignatureVerifier]:
    verifier = _outcome_attestation_verifier(issuer_keys)
    service = OutcomeAttestationService(
        signer=verifier,
        issuer=PartyRef(type="service", id="https://actenon-cloud.local/issuer", display_name="Actenon Cloud"),
    )
    return service, verifier


def _context(pccb: PCCB) -> DynamicContextInput:
    return DynamicContextInput(
        request_id="req_cloud_invoice_vector_v1",
        audience=pccb.audience,
        scope_capabilities=pccb.scope.capabilities,
        now=pccb.issued_at.replace(minute=5),
    )


@unittest.skipIf(cryptography is None, "cryptography is required for Ed25519 vector verification")
class CloudInvoicePaymentConformanceVectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action_intent_payload = _load_json("action_intent.json")
        self.pccb_payload = _load_json("pccb.json")
        self.issuer_keys_payload = _load_json("issuer_keys.json")
        self.intent = ActionIntent.from_dict(self.action_intent_payload)
        self.pccb = PCCB.from_dict(self.pccb_payload)

    def test_cloud_invoice_payment_pccb_verifies_through_well_known_resolver(self) -> None:
        _verifier(self.issuer_keys_payload).verify(
            self.intent,
            self.pccb,
            _context(self.pccb),
        )

    def test_amount_mutation_fails(self) -> None:
        mutated_intent = ActionIntent.from_dict(
            _load_json("mutations/amount_changed_action_intent.json")
        )
        self._assert_verification_fails(
            mutated_intent,
            self.pccb,
            self.issuer_keys_payload,
            expected_code="ACTION_MISMATCH",
        )

    def test_audience_mutation_fails(self) -> None:
        mutated_pccb = PCCB.from_dict(_load_json("mutations/audience_changed_pccb.json"))
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="AUDIENCE_MISMATCH",
            context=_context(self.pccb),
        )

    def test_expiry_mutation_fails(self) -> None:
        mutated_pccb = PCCB.from_dict(_load_json("mutations/expired_pccb.json"))
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="PROOF_EXPIRED",
        )

    def test_action_hash_mutation_fails(self) -> None:
        mutated_pccb = PCCB.from_dict(_load_json("mutations/action_hash_changed_pccb.json"))
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="ACTION_HASH_MISMATCH",
        )

    def test_signature_mutation_fails(self) -> None:
        mutated_pccb = PCCB.from_dict(_load_json("mutations/signature_changed_pccb.json"))
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="SIGNATURE_INVALID",
        )

    def test_wrong_kid_fails(self) -> None:
        mutated_pccb = PCCB.from_dict(_load_json("mutations/wrong_kid_pccb.json"))
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="SIGNATURE_INVALID",
        )

    def test_wrong_purpose_fails(self) -> None:
        wrong_purpose_keys = _load_json("mutations/wrong_purpose_issuer_keys.json")
        self._assert_verification_fails(
            self.intent,
            self.pccb,
            wrong_purpose_keys,
            expected_code="SIGNATURE_INVALID",
        )

    def test_signed_field_mutation_fails_even_with_same_signature(self) -> None:
        mutated_payload = copy.deepcopy(self.pccb_payload)
        mutated_payload["action"]["parameters"]["amount_minor"] = 810000
        mutated_pccb = PCCB.from_dict(mutated_payload)
        self._assert_verification_fails(
            self.intent,
            mutated_pccb,
            self.issuer_keys_payload,
            expected_code="ACTION_MISMATCH",
        )

    def test_cloud_receipt_attestation_verifies_through_well_known_resolver(self) -> None:
        service, verifier = _outcome_attestation_service(self.issuer_keys_payload)

        receipt = service.verify_receipt_attestation(
            _load_json("receipt_attestation.json"),
            verifier=verifier,
        )

        self.assertEqual("receipt_cloud_invoice_v1", receipt["receipt_id"])
        self.assertEqual("executed", receipt["outcome"])

    def test_cloud_refusal_attestation_verifies_through_well_known_resolver(self) -> None:
        service, verifier = _outcome_attestation_service(self.issuer_keys_payload)

        refusal = service.verify_refusal_attestation(
            _load_json("refusal_attestation.json"),
            verifier=verifier,
        )

        self.assertEqual("refusal_cloud_invoice_v1", refusal["refusal_id"])
        self.assertEqual("refused", refusal["outcome"])

    def test_external_anchor_can_be_added_without_invalidating_issuer_signature(self) -> None:
        payload = _load_json("receipt_attestation.json")
        payload["external_anchors"].append(
            {
                "type": "opaque",
                "anchor_id": "anchor_demo",
                "anchored_at": "2026-01-15T12:03:00Z",
                "artifact_digest": payload["unsigned_payload"]["artifact_digest"],
                "trust_root": {"type": "network_id", "id": "demo"},
                "proof": {"format": "opaque", "value": None},
                "metadata": {},
            }
        )
        service, verifier = _outcome_attestation_service(self.issuer_keys_payload)

        receipt = service.verify_receipt_attestation(payload, verifier=verifier)

        self.assertEqual("receipt_cloud_invoice_v1", receipt["receipt_id"])

    def test_receipt_attestation_outcome_artifact_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_outcome_artifact_changed.json"),
            self.issuer_keys_payload,
        )

    def test_receipt_attestation_digest_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_artifact_digest_changed.json"),
            self.issuer_keys_payload,
        )

    def test_receipt_attestation_proof_binding_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_proof_binding_changed.json"),
            self.issuer_keys_payload,
        )

    def test_receipt_attestation_signature_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_signature_changed.json"),
            self.issuer_keys_payload,
        )

    def test_receipt_attestation_issuer_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_issuer_changed.json"),
            self.issuer_keys_payload,
        )

    def test_receipt_attestation_issued_at_tampering_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("mutations/receipt_attestation_issued_at_changed.json"),
            self.issuer_keys_payload,
        )

    def test_refusal_attestation_signature_tampering_fails(self) -> None:
        self._assert_refusal_attestation_fails(
            _load_json("mutations/refusal_attestation_signature_changed.json"),
            self.issuer_keys_payload,
        )

    def test_refusal_attestation_issuer_tampering_fails(self) -> None:
        self._assert_refusal_attestation_fails(
            _load_json("mutations/refusal_attestation_issuer_changed.json"),
            self.issuer_keys_payload,
        )

    def test_refusal_attestation_issued_at_tampering_fails(self) -> None:
        self._assert_refusal_attestation_fails(
            _load_json("mutations/refusal_attestation_issued_at_changed.json"),
            self.issuer_keys_payload,
        )

    def _assert_refusal_attestation_fails(
        self,
        attestation_payload: dict[str, object],
        issuer_keys: dict[str, object],
    ) -> None:
        service, verifier = _outcome_attestation_service(issuer_keys)
        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_refusal_attestation(
                attestation_payload,
                verifier=verifier,
            )

    def test_receipt_attestation_wrong_purpose_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("receipt_attestation.json"),
            _load_json("mutations/outcome_attestation_wrong_purpose_issuer_keys.json"),
        )

    def test_receipt_attestation_hard_revoked_without_anchor_fails(self) -> None:
        self._assert_receipt_attestation_fails(
            _load_json("receipt_attestation.json"),
            _load_json("mutations/outcome_attestation_hard_revoked_issuer_keys.json"),
        )

    def _assert_verification_fails(
        self,
        intent: ActionIntent,
        pccb: PCCB,
        issuer_keys: dict[str, object],
        *,
        expected_code: str,
        context: DynamicContextInput | None = None,
    ) -> None:
        with self.assertRaises(ProofVerificationError) as raised:
            _verifier(issuer_keys).verify(intent, pccb, context or _context(pccb))
        self.assertEqual(expected_code, raised.exception.refusal_code)

    def _assert_receipt_attestation_fails(
        self,
        attestation_payload: dict[str, object],
        issuer_keys: dict[str, object],
    ) -> None:
        service, verifier = _outcome_attestation_service(issuer_keys)
        with self.assertRaises(OutcomeAttestationVerificationError):
            service.verify_receipt_attestation(attestation_payload, verifier=verifier)
