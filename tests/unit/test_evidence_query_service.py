from __future__ import annotations

import unittest
from datetime import datetime, timezone

from actenon.api import ActionIntentIntakeService, build_refund_action_intent_payload
from actenon.core.errors import RefusalException
from actenon.evidence import EvidenceQuery, EvidenceQueryService, EvidenceVerdict, InMemoryActionIntentStore, InMemoryPCCBStore
from actenon.models import AudienceRef, DynamicContextInput, PartyRef, PolicyDecision, receipt_evidence_ref
from actenon.proof import PCCBMinter, build_local_proof_signer
from actenon.receipts import (
    InMemoryOutcomeWriter,
    InMemoryReceiptStore,
    InMemoryRefusalStore,
    ReceiptFactory,
    RefusalFactory,
)


class EvidenceQueryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 4, 11, 16, 0, tzinfo=timezone.utc)
        self.intake = ActionIntentIntakeService()
        self.signer = build_local_proof_signer()
        self.intent_store = InMemoryActionIntentStore()
        self.pccb_store = InMemoryPCCBStore()
        self.receipt_store = InMemoryReceiptStore()
        self.refusal_store = InMemoryRefusalStore()
        self.outcome_writer = InMemoryOutcomeWriter(
            receipt_store=self.receipt_store,
            refusal_store=self.refusal_store,
        )
        self.receipt_factory = ReceiptFactory()
        self.refusal_factory = RefusalFactory()
        self.query_service = EvidenceQueryService(
            intent_store=self.intent_store,
            pccb_store=self.pccb_store,
            receipt_store=self.receipt_store,
            refusal_store=self.refusal_store,
            max_chain_depth=4,
        )

    def _context(self, *, request_id: str) -> DynamicContextInput:
        return DynamicContextInput(
            request_id=request_id,
            audience=AudienceRef(type="service", id="refund-endpoint"),
            scope_capabilities=("refund.execute",),
            now=self.now,
            facts={"risk_level": "normal"},
        )

    def _intent(self, *, intent_id: str, payment_id: str, evidence_refs: list[dict[str, object]] | None = None):
        payload = build_refund_action_intent_payload(
            intent_id=intent_id,
            tenant_id="tenant_demo",
            requester_id="demo_actor",
            payment_id=payment_id,
            amount_minor=1200,
            currency="USD",
            issued_at=self.now,
            ttl_seconds=300,
            evidence_refs=evidence_refs,
        )
        return self.intake.parse(payload)

    def _mint_pccb(self, *, intent, request_id: str, pccb_id: str):
        context = self._context(request_id=request_id)
        pccb = PCCBMinter(
            signer=self.signer,
            issuer=PartyRef(type="service", id="local_kernel"),
            pccb_id_factory=lambda: pccb_id,
            nonce_factory=lambda: f"nonce-{pccb_id}",
        ).mint(
            intent,
            decision=PolicyDecision(
                outcome="allow",
                summary="Allow for evidence-query test.",
                rule_evaluations=(),
                reason_codes=("ALLOW",),
            ),
            context=context,
        )
        self.intent_store.put_intent(intent)
        self.pccb_store.put_pccb(pccb)
        return context, pccb

    def _write_execution_receipt(self, *, intent, pccb, context, receipt_id: str):
        receipt = self.receipt_factory.create_execution_receipt(
            intent,
            context,
            pccb_id=pccb.pccb_id,
            escrow_id=f"esc_{pccb.pccb_id}",
            payload={"external_reference": f"ext_{receipt_id}"},
            action_hash=pccb.action_hash,
        )
        receipt = type(receipt)(
            receipt_id=receipt_id,
            intent_id=receipt.intent_id,
            occurred_at=receipt.occurred_at,
            outcome=receipt.outcome,
            tenant=receipt.tenant,
            subject=receipt.subject,
            action=receipt.action,
            target=receipt.target,
            summary=receipt.summary,
            phase=receipt.phase,
            correlation=receipt.correlation,
            reason_codes=receipt.reason_codes,
            follow_up=receipt.follow_up,
            side_effects=receipt.side_effects,
            details=receipt.details,
            metadata=receipt.metadata,
            extensions=receipt.extensions,
        )
        self.outcome_writer.write_receipt(receipt)
        return receipt

    def _write_refusal_chain(self, *, intent, pccb, context, refusal_id: str, receipt_id: str):
        refusal = self.refusal_factory.create_from_exception(
            RefusalException(
                category="proof",
                refusal_code="AUDIENCE_MISMATCH",
                message="The proof audience does not match this endpoint.",
            ),
            occurred_at=context.now,
            intent=intent,
            context=context,
            pccb_id=pccb.pccb_id,
            escrow_id=f"esc_{pccb.pccb_id}",
            action_hash=pccb.action_hash,
        )
        refusal = type(refusal)(
            refusal_id=refusal_id,
            intent_id=refusal.intent_id,
            category=refusal.category,
            reason_code=refusal.reason_code,
            message=refusal.message,
            retryable=refusal.retryable,
            refused_at=refusal.refused_at,
            tenant=refusal.tenant,
            subject=refusal.subject,
            audience=refusal.audience,
            action=refusal.action,
            target=refusal.target,
            correlation=refusal.correlation,
            rule_refs=refusal.rule_refs,
            violations=refusal.violations,
            details=refusal.details,
            extensions=refusal.extensions,
        )
        self.outcome_writer.write_refusal(refusal)
        receipt = self.receipt_factory.create_refused_receipt(intent, context, refusal)
        receipt = type(receipt)(
            receipt_id=receipt_id,
            intent_id=receipt.intent_id,
            occurred_at=receipt.occurred_at,
            outcome=receipt.outcome,
            tenant=receipt.tenant,
            subject=receipt.subject,
            action=receipt.action,
            target=receipt.target,
            summary=receipt.summary,
            phase=receipt.phase,
            correlation=receipt.correlation,
            reason_codes=receipt.reason_codes,
            follow_up=receipt.follow_up,
            side_effects=receipt.side_effects,
            details=receipt.details,
            metadata=receipt.metadata,
            extensions=receipt.extensions,
        )
        self.outcome_writer.write_receipt(receipt)
        return refusal, receipt

    def test_verified_execution_by_action_hash(self) -> None:
        intent = self._intent(intent_id="intent_exec_001", payment_id="pay_exec_001")
        context, pccb = self._mint_pccb(intent=intent, request_id="req_exec_001", pccb_id="pccb_exec_001")
        receipt = self._write_execution_receipt(intent=intent, pccb=pccb, context=context, receipt_id="rcpt_exec_001")

        result = self.query_service.query(EvidenceQuery(action_hash=pccb.action_hash.value))

        self.assertEqual(EvidenceVerdict.VERIFIED_EXECUTION, result.verdict)
        self.assertEqual(receipt.receipt_id, result.receipt_id)
        self.assertEqual(pccb.pccb_id, result.pccb_id)

    def test_proof_not_found_by_pccb_id(self) -> None:
        result = self.query_service.query(EvidenceQuery(pccb_id="pccb_missing_001"))

        self.assertEqual(EvidenceVerdict.PROOF_NOT_FOUND, result.verdict)

    def test_hash_mismatch_by_receipt_id(self) -> None:
        intent = self._intent(intent_id="intent_hash_001", payment_id="pay_hash_001")
        context, pccb = self._mint_pccb(intent=intent, request_id="req_hash_001", pccb_id="pccb_hash_001")
        pccb = type(pccb)(
            pccb_id=pccb.pccb_id,
            issued_at=pccb.issued_at,
            not_before=pccb.not_before,
            expires_at=pccb.expires_at,
            issuer=pccb.issuer,
            subject=pccb.subject,
            tenant=pccb.tenant,
            audience=pccb.audience,
            action=pccb.action,
            target=pccb.target,
            scope=pccb.scope,
            nonce=pccb.nonce,
            action_hash=type(pccb.action_hash)(
                algorithm=pccb.action_hash.algorithm,
                canonicalization=pccb.action_hash.canonicalization,
                value="deadbeef" * 8,
            ),
            signature=pccb.signature,
            intent_id=pccb.intent_id,
            escrow_id=pccb.escrow_id,
            extensions=pccb.extensions,
        )
        self.pccb_store.put_pccb(pccb)
        receipt = self._write_execution_receipt(intent=intent, pccb=pccb, context=context, receipt_id="rcpt_hash_001")

        result = self.query_service.query(EvidenceQuery(receipt_id=receipt.receipt_id))

        self.assertEqual(EvidenceVerdict.HASH_MISMATCH, result.verdict)

    def test_verified_refusal_by_pccb_id(self) -> None:
        intent = self._intent(intent_id="intent_refusal_001", payment_id="pay_refusal_001")
        context, pccb = self._mint_pccb(intent=intent, request_id="req_refusal_001", pccb_id="pccb_refusal_001")
        refusal, receipt = self._write_refusal_chain(
            intent=intent,
            pccb=pccb,
            context=context,
            refusal_id="rfsl_refusal_001",
            receipt_id="rcpt_refusal_001",
        )

        result = self.query_service.query(EvidenceQuery(pccb_id=pccb.pccb_id))

        self.assertEqual(EvidenceVerdict.VERIFIED_REFUSAL, result.verdict)
        self.assertEqual(refusal.refusal_id, result.refusal_id)
        self.assertEqual(receipt.receipt_id, result.receipt_id)

    def test_multi_step_chain_traversal_by_intent_id(self) -> None:
        parent_intent = self._intent(intent_id="intent_parent_001", payment_id="pay_parent_001")
        parent_context, parent_pccb = self._mint_pccb(intent=parent_intent, request_id="req_parent_001", pccb_id="pccb_parent_001")
        parent_receipt = self._write_execution_receipt(
            intent=parent_intent,
            pccb=parent_pccb,
            context=parent_context,
            receipt_id="rcpt_parent_001",
        )

        child_intent = self._intent(
            intent_id="intent_child_001",
            payment_id="pay_child_001",
            evidence_refs=[receipt_evidence_ref(parent_receipt).to_dict()],
        )
        child_context, child_pccb = self._mint_pccb(intent=child_intent, request_id="req_child_001", pccb_id="pccb_child_001")
        child_receipt = self._write_execution_receipt(
            intent=child_intent,
            pccb=child_pccb,
            context=child_context,
            receipt_id="rcpt_child_001",
        )

        result = self.query_service.query(EvidenceQuery(intent_id=child_intent.intent_id))

        self.assertEqual(EvidenceVerdict.VERIFIED_EXECUTION, result.verdict)
        self.assertEqual(child_receipt.receipt_id, result.receipt_id)
        self.assertEqual(1, result.chain_depth)

    def test_chain_broken_when_receipt_reference_missing(self) -> None:
        missing_receipt_ref = {
            "type": "actenon.receipt",
            "value": "rcpt_missing_001",
            "digest": {
                "algorithm": "sha-256",
                "canonicalization": "RFC8785-JCS",
                "value": "0" * 64,
            },
        }
        intent = self._intent(
            intent_id="intent_broken_001",
            payment_id="pay_broken_001",
            evidence_refs=[missing_receipt_ref],
        )
        context, pccb = self._mint_pccb(intent=intent, request_id="req_broken_001", pccb_id="pccb_broken_001")
        self._write_execution_receipt(intent=intent, pccb=pccb, context=context, receipt_id="rcpt_broken_001")

        result = self.query_service.query(EvidenceQuery(intent_id=intent.intent_id))

        self.assertEqual(EvidenceVerdict.CHAIN_BROKEN, result.verdict)


if __name__ == "__main__":
    unittest.main()
