from __future__ import annotations

from dataclasses import dataclass

from actenon.models import ActionIntent, DigestSpec, EVIDENCE_TYPE_RECEIPT, build_artifact_digest
from actenon.models.runtime import DynamicContextInput, RuleEvaluation
from actenon.receipts import ReceiptStore


@dataclass(frozen=True)
class ReceiptEvidenceVerificationRule:
    receipt_store: ReceiptStore | None = None
    allowed_outcomes: tuple[str, ...] = ("executed",)
    required_capability: str | None = None
    rule_id: str = "hard.evidence.receipt_chain"

    def evaluate(self, intent: ActionIntent, context: DynamicContextInput) -> RuleEvaluation | None:
        receipt_refs = tuple(item for item in intent.evidence_refs if item.type == EVIDENCE_TYPE_RECEIPT)
        if not receipt_refs:
            return None
        if self.receipt_store is None:
            return RuleEvaluation(
                rule_id=self.rule_id,
                outcome="deny",
                reason_code="RECEIPT_EVIDENCE_STORE_UNAVAILABLE",
                summary="Receipt evidence was supplied but no receipt lookup store is configured.",
                details={"receipt_ref_count": len(receipt_refs)},
            )

        for receipt_ref in receipt_refs:
            receipt = self.receipt_store.get_receipt(receipt_ref.value)
            if receipt is None:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="RECEIPT_EVIDENCE_MISSING",
                    summary="The referenced receipt evidence could not be loaded.",
                    details={"receipt_id": receipt_ref.value},
                )

            try:
                declared_digest = DigestSpec.from_dict(receipt_ref.digest, "evidence_ref.digest")
            except ValueError:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="RECEIPT_EVIDENCE_DIGEST_INVALID",
                    summary="Receipt evidence must declare a complete digest for the referenced receipt.",
                    details={"receipt_id": receipt_ref.value},
                )

            actual_digest = build_artifact_digest(receipt)
            if declared_digest != actual_digest:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="RECEIPT_EVIDENCE_DIGEST_MISMATCH",
                    summary="The referenced receipt digest does not match the loaded receipt artifact.",
                    details={
                        "receipt_id": receipt_ref.value,
                        "expected_digest": actual_digest.to_dict(),
                        "declared_digest": declared_digest.to_dict(),
                    },
                )

            if receipt.outcome not in self.allowed_outcomes:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="RECEIPT_EVIDENCE_OUTCOME_INVALID",
                    summary="The referenced receipt outcome is not suitable for this evidence chain.",
                    details={
                        "receipt_id": receipt_ref.value,
                        "allowed_outcomes": list(self.allowed_outcomes),
                        "observed_outcome": receipt.outcome,
                    },
                )

            if self.required_capability is not None and receipt.action.capability != self.required_capability:
                return RuleEvaluation(
                    rule_id=self.rule_id,
                    outcome="deny",
                    reason_code="RECEIPT_EVIDENCE_CAPABILITY_MISMATCH",
                    summary="The referenced receipt capability does not satisfy the configured receipt-chain requirement.",
                    details={
                        "receipt_id": receipt_ref.value,
                        "required_capability": self.required_capability,
                        "observed_capability": receipt.action.capability,
                    },
                )

        return None
