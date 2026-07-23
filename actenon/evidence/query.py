from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from actenon.models import ActionIntent, DigestSpec, EVIDENCE_TYPE_RECEIPT, PCCB, Receipt, Refusal, build_artifact_digest
from actenon.proof import build_action_hash_input
from actenon.proof.canonical import sha256_hex
from actenon.receipts import ReceiptStore, RefusalStore

from .stores import ActionIntentStore, PCCBStore


class EvidenceVerdict(str, Enum):
    VERIFIED_EXECUTION = "VERIFIED_EXECUTION"
    VERIFIED_REFUSAL = "VERIFIED_REFUSAL"
    PROOF_NOT_FOUND = "PROOF_NOT_FOUND"
    HASH_MISMATCH = "HASH_MISMATCH"
    CHAIN_BROKEN = "CHAIN_BROKEN"


@dataclass(frozen=True)
class EvidenceQuery:
    receipt_id: str | None = None
    pccb_id: str | None = None
    intent_id: str | None = None
    action_hash: str | None = None

    def __post_init__(self) -> None:
        populated = sum(
            value is not None
            for value in (self.receipt_id, self.pccb_id, self.intent_id, self.action_hash)
        )
        if populated != 1:
            raise ValueError("EvidenceQuery must specify exactly one of receipt_id, pccb_id, intent_id, or action_hash")


@dataclass(frozen=True)
class EvidenceResult:
    verdict: EvidenceVerdict
    summary: str
    receipt_id: str | None = None
    refusal_id: str | None = None
    pccb_id: str | None = None
    intent_id: str | None = None
    action_hash: str | None = None
    chain_depth: int = 0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceQueryService:
    intent_store: ActionIntentStore | None = None
    pccb_store: PCCBStore | None = None
    receipt_store: ReceiptStore | None = None
    refusal_store: RefusalStore | None = None
    max_chain_depth: int = 8

    def query(self, evidence_query: EvidenceQuery) -> EvidenceResult:
        if evidence_query.receipt_id is not None:
            return self._query_by_receipt_id(evidence_query.receipt_id)
        if evidence_query.pccb_id is not None:
            return self._query_by_pccb_id(evidence_query.pccb_id)
        if evidence_query.intent_id is not None:
            return self._query_by_intent_id(evidence_query.intent_id)
        if evidence_query.action_hash is not None:
            return self._query_by_action_hash(evidence_query.action_hash)
        raise AssertionError("unreachable")

    def _query_by_receipt_id(self, receipt_id: str) -> EvidenceResult:
        receipt = self.receipt_store.get_receipt(receipt_id) if self.receipt_store is not None else None
        if receipt is None:
            return self._result(EvidenceVerdict.PROOF_NOT_FOUND, "No receipt was found for the requested receipt_id.", details={"receipt_id": receipt_id})
        return self._verify_from_receipt(receipt)

    def _query_by_pccb_id(self, pccb_id: str) -> EvidenceResult:
        receipt = self._prefer_receipt(item for item in self._list_receipts() if item.correlation is not None and item.correlation.pccb_id == pccb_id)
        refusal = self._prefer_refusal(item for item in self._list_refusals() if item.correlation is not None and item.correlation.pccb_id == pccb_id)
        pccb = self.pccb_store.get_pccb(pccb_id) if self.pccb_store is not None else None

        if refusal is not None:
            return self._verify_from_refusal(refusal, paired_receipt=receipt)
        if receipt is not None:
            return self._verify_from_receipt(receipt, pccb=pccb)
        if pccb is not None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "A PCCB exists for the requested execution, but no receipt or refusal chain was found.",
                pccb_id=pccb.pccb_id,
                intent_id=pccb.intent_id,
                action_hash=pccb.action_hash.value,
            )
        return self._result(EvidenceVerdict.PROOF_NOT_FOUND, "No proof or outcome chain was found for the requested pccb_id.", details={"pccb_id": pccb_id})

    def _query_by_intent_id(self, intent_id: str) -> EvidenceResult:
        receipt = self._prefer_receipt(item for item in self._list_receipts() if item.intent_id == intent_id)
        refusal = self._prefer_refusal(item for item in self._list_refusals() if item.intent_id == intent_id)
        pccb = self._prefer_pccb(item for item in self._list_pccbs() if item.intent_id == intent_id)
        intent = self.intent_store.get_intent(intent_id) if self.intent_store is not None else None

        if refusal is not None:
            return self._verify_from_refusal(refusal, paired_receipt=receipt, intent=intent, pccb=pccb)
        if receipt is not None:
            return self._verify_from_receipt(receipt, intent=intent, pccb=pccb)
        if pccb is not None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "Proof exists for the requested intent, but no terminal outcome artifact was found.",
                pccb_id=pccb.pccb_id,
                intent_id=intent_id,
                action_hash=pccb.action_hash.value,
            )
        return self._result(EvidenceVerdict.PROOF_NOT_FOUND, "No proof or outcome chain was found for the requested intent_id.", intent_id=intent_id)

    def _query_by_action_hash(self, action_hash: str) -> EvidenceResult:
        pccb = self._prefer_pccb(item for item in self._list_pccbs() if item.action_hash.value == action_hash)
        if pccb is not None:
            return self._query_by_pccb_id(pccb.pccb_id)

        receipt = self._prefer_receipt(
            item
            for item in self._list_receipts()
            if item.correlation is not None and item.correlation.action_hash is not None and item.correlation.action_hash.value == action_hash
        )
        refusal = self._prefer_refusal(
            item
            for item in self._list_refusals()
            if item.correlation is not None and item.correlation.action_hash is not None and item.correlation.action_hash.value == action_hash
        )
        if refusal is not None:
            return self._verify_from_refusal(refusal, paired_receipt=receipt)
        if receipt is not None:
            return self._verify_from_receipt(receipt)
        return self._result(EvidenceVerdict.PROOF_NOT_FOUND, "No proof or outcome chain was found for the requested action_hash.", action_hash=action_hash)

    def _verify_from_receipt(
        self,
        receipt: Receipt,
        *,
        intent: ActionIntent | None = None,
        pccb: PCCB | None = None,
    ) -> EvidenceResult:
        if receipt.outcome == "refused":
            paired_refusal = self._prefer_refusal(
                item
                for item in self._list_refusals()
                if receipt.correlation is not None
                and item.correlation is not None
                and item.correlation.pccb_id == receipt.correlation.pccb_id
                and item.intent_id == receipt.intent_id
            )
            if paired_refusal is None:
                return self._result(
                    EvidenceVerdict.CHAIN_BROKEN,
                    "The refused receipt does not have a matching refusal artifact.",
                    receipt_id=receipt.receipt_id,
                    intent_id=receipt.intent_id,
                )
            return self._verify_from_refusal(paired_refusal, paired_receipt=receipt, intent=intent, pccb=pccb)

        if receipt.outcome != "executed":
            return self._result(
                EvidenceVerdict.PROOF_NOT_FOUND,
                "The referenced receipt is not a terminal execution artifact.",
                receipt_id=receipt.receipt_id,
                intent_id=receipt.intent_id,
                details={"outcome": receipt.outcome},
            )

        resolved_intent = intent or self._load_intent(receipt.intent_id)
        if resolved_intent is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The execution receipt does not have a loadable Action Intent.",
                receipt_id=receipt.receipt_id,
                intent_id=receipt.intent_id,
            )
        if receipt.correlation is None or receipt.correlation.pccb_id is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The execution receipt does not carry a correlated PCCB id.",
                receipt_id=receipt.receipt_id,
                intent_id=receipt.intent_id,
            )
        resolved_pccb = pccb or self._load_pccb(receipt.correlation.pccb_id)
        if resolved_pccb is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The execution receipt points at a PCCB that is not available in the local evidence stores.",
                receipt_id=receipt.receipt_id,
                pccb_id=receipt.correlation.pccb_id,
                intent_id=receipt.intent_id,
            )
        if resolved_pccb.intent_id is not None and resolved_pccb.intent_id != resolved_intent.intent_id:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The execution receipt points at a PCCB whose intent_id does not match the loaded Action Intent.",
                receipt_id=receipt.receipt_id,
                pccb_id=resolved_pccb.pccb_id,
                intent_id=resolved_intent.intent_id,
                details={"pccb_intent_id": resolved_pccb.intent_id},
            )

        hash_verdict = self._verify_hash_integrity(intent=resolved_intent, pccb=resolved_pccb, receipt=receipt)
        if hash_verdict is not None:
            return hash_verdict

        chain_verdict, chain_depth = self._verify_receipt_evidence_chain(
            intent=resolved_intent,
            remaining_depth=self.max_chain_depth,
            seen_receipt_ids=set(),
        )
        if chain_verdict is not None:
            return self._with_defaults(chain_verdict, receipt=receipt, pccb=resolved_pccb, intent=resolved_intent, chain_depth=chain_depth)
        return self._result(
            EvidenceVerdict.VERIFIED_EXECUTION,
            "A valid execution receipt, PCCB, and receipt-evidence chain were found.",
            receipt_id=receipt.receipt_id,
            pccb_id=resolved_pccb.pccb_id,
            intent_id=resolved_intent.intent_id,
            action_hash=resolved_pccb.action_hash.value,
            chain_depth=chain_depth,
        )

    def _verify_from_refusal(
        self,
        refusal: Refusal,
        *,
        paired_receipt: Receipt | None = None,
        intent: ActionIntent | None = None,
        pccb: PCCB | None = None,
    ) -> EvidenceResult:
        if refusal.intent_id is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal does not identify the Action Intent it belongs to.",
                refusal_id=refusal.refusal_id,
            )
        resolved_intent = intent or self._load_intent(refusal.intent_id)
        if resolved_intent is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal does not have a loadable Action Intent.",
                refusal_id=refusal.refusal_id,
                intent_id=refusal.intent_id,
            )
        if refusal.correlation is None or refusal.correlation.pccb_id is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal does not carry a correlated PCCB id.",
                refusal_id=refusal.refusal_id,
                intent_id=resolved_intent.intent_id,
            )
        resolved_pccb = pccb or self._load_pccb(refusal.correlation.pccb_id)
        if resolved_pccb is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal points at a PCCB that is not available in the local evidence stores.",
                refusal_id=refusal.refusal_id,
                pccb_id=refusal.correlation.pccb_id,
                intent_id=resolved_intent.intent_id,
            )
        if resolved_pccb.intent_id is not None and resolved_pccb.intent_id != resolved_intent.intent_id:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal points at a PCCB whose intent_id does not match the loaded Action Intent.",
                refusal_id=refusal.refusal_id,
                pccb_id=resolved_pccb.pccb_id,
                intent_id=resolved_intent.intent_id,
                details={"pccb_intent_id": resolved_pccb.intent_id},
            )
        if paired_receipt is None:
            paired_receipt = self._prefer_receipt(
                item
                for item in self._list_receipts()
                if item.outcome == "refused"
                and item.intent_id == resolved_intent.intent_id
                and item.correlation is not None
                and item.correlation.pccb_id == resolved_pccb.pccb_id
            )
        if paired_receipt is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The refusal does not have a matching refused receipt artifact.",
                refusal_id=refusal.refusal_id,
                pccb_id=resolved_pccb.pccb_id,
                intent_id=resolved_intent.intent_id,
            )
        if paired_receipt.outcome != "refused":
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "The receipt paired with the refusal is not a refused execution receipt.",
                receipt_id=paired_receipt.receipt_id,
                refusal_id=refusal.refusal_id,
                pccb_id=resolved_pccb.pccb_id,
                intent_id=resolved_intent.intent_id,
                details={"receipt_outcome": paired_receipt.outcome},
            )
        hash_verdict = self._verify_hash_integrity(intent=resolved_intent, pccb=resolved_pccb, receipt=paired_receipt, refusal=refusal)
        if hash_verdict is not None:
            return hash_verdict
        chain_verdict, chain_depth = self._verify_receipt_evidence_chain(
            intent=resolved_intent,
            remaining_depth=self.max_chain_depth,
            seen_receipt_ids=set(),
        )
        if chain_verdict is not None:
            return self._with_defaults(chain_verdict, receipt=paired_receipt, refusal=refusal, pccb=resolved_pccb, intent=resolved_intent, chain_depth=chain_depth)
        return self._result(
            EvidenceVerdict.VERIFIED_REFUSAL,
            "A valid refusal, refused receipt, PCCB, and receipt-evidence chain were found.",
            receipt_id=paired_receipt.receipt_id,
            refusal_id=refusal.refusal_id,
            pccb_id=resolved_pccb.pccb_id,
            intent_id=resolved_intent.intent_id,
            action_hash=resolved_pccb.action_hash.value,
            chain_depth=chain_depth,
        )

    def _verify_hash_integrity(
        self,
        *,
        intent: ActionIntent,
        pccb: PCCB,
        receipt: Receipt | None = None,
        refusal: Refusal | None = None,
    ) -> EvidenceResult | None:
        expected_action_hash = sha256_hex(build_action_hash_input(intent))
        if pccb.action_hash.value != expected_action_hash:
            return self._result(
                EvidenceVerdict.HASH_MISMATCH,
                "The PCCB action hash does not match the canonical Action Intent hash.",
                pccb_id=pccb.pccb_id,
                intent_id=intent.intent_id,
                action_hash=pccb.action_hash.value,
                details={"expected_action_hash": expected_action_hash},
            )
        if receipt is not None and receipt.correlation is not None and receipt.correlation.action_hash is not None:
            if receipt.correlation.action_hash.value != expected_action_hash:
                return self._result(
                    EvidenceVerdict.HASH_MISMATCH,
                    "The receipt correlation action hash does not match the canonical Action Intent hash.",
                    receipt_id=receipt.receipt_id,
                    pccb_id=pccb.pccb_id,
                    intent_id=intent.intent_id,
                    action_hash=receipt.correlation.action_hash.value,
                    details={"expected_action_hash": expected_action_hash},
                )
        if refusal is not None and refusal.correlation is not None and refusal.correlation.action_hash is not None:
            if refusal.correlation.action_hash.value != expected_action_hash:
                return self._result(
                    EvidenceVerdict.HASH_MISMATCH,
                    "The refusal correlation action hash does not match the canonical Action Intent hash.",
                    refusal_id=refusal.refusal_id,
                    pccb_id=pccb.pccb_id,
                    intent_id=intent.intent_id,
                    action_hash=refusal.correlation.action_hash.value,
                    details={"expected_action_hash": expected_action_hash},
                )
        return None

    def _verify_receipt_evidence_chain(
        self,
        *,
        intent: ActionIntent,
        remaining_depth: int,
        seen_receipt_ids: set[str],
    ) -> tuple[EvidenceResult | None, int]:
        receipt_refs = tuple(item for item in intent.evidence_refs if item.type == EVIDENCE_TYPE_RECEIPT)
        if not receipt_refs:
            return None, 0
        if self.receipt_store is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "Receipt evidence references are present, but no receipt store is configured for chain traversal.",
                intent_id=intent.intent_id,
            ), 0
        if self.intent_store is None:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "Receipt evidence references are present, but no Action Intent store is configured for chain traversal.",
                intent_id=intent.intent_id,
            ), 0
        if remaining_depth <= 0:
            return self._result(
                EvidenceVerdict.CHAIN_BROKEN,
                "Receipt evidence chain exceeded the configured maximum traversal depth.",
                intent_id=intent.intent_id,
                details={"max_chain_depth": self.max_chain_depth},
            ), 0

        max_depth = 0
        for receipt_ref in receipt_refs:
            referenced_receipt = self.receipt_store.get_receipt(receipt_ref.value)
            if referenced_receipt is None:
                return self._result(
                    EvidenceVerdict.CHAIN_BROKEN,
                    "A referenced receipt in the evidence chain could not be loaded.",
                    intent_id=intent.intent_id,
                    receipt_id=receipt_ref.value,
                ), max_depth
            if referenced_receipt.receipt_id in seen_receipt_ids:
                return self._result(
                    EvidenceVerdict.CHAIN_BROKEN,
                    "A receipt evidence cycle was detected during chain traversal.",
                    intent_id=intent.intent_id,
                    receipt_id=referenced_receipt.receipt_id,
                ), max_depth
            try:
                declared_digest = DigestSpec.from_dict(receipt_ref.digest, "evidence_ref.digest")
            except ValueError:
                return self._result(
                    EvidenceVerdict.HASH_MISMATCH,
                    "A receipt evidence reference declared an invalid digest payload.",
                    intent_id=intent.intent_id,
                    receipt_id=referenced_receipt.receipt_id,
                ), max_depth
            actual_digest = build_artifact_digest(referenced_receipt)
            if declared_digest != actual_digest:
                return self._result(
                    EvidenceVerdict.HASH_MISMATCH,
                    "A referenced receipt digest does not match the canonical receipt artifact hash.",
                    intent_id=intent.intent_id,
                    receipt_id=referenced_receipt.receipt_id,
                    details={"declared_digest": declared_digest.to_dict(), "actual_digest": actual_digest.to_dict()},
                ), max_depth
            parent_intent = self.intent_store.get_intent(referenced_receipt.intent_id)
            if parent_intent is None:
                return self._result(
                    EvidenceVerdict.CHAIN_BROKEN,
                    "A referenced receipt does not have a loadable parent Action Intent for continued chain traversal.",
                    intent_id=intent.intent_id,
                    receipt_id=referenced_receipt.receipt_id,
                ), max_depth
            nested_verdict, nested_depth = self._verify_receipt_evidence_chain(
                intent=parent_intent,
                remaining_depth=remaining_depth - 1,
                seen_receipt_ids=seen_receipt_ids | {referenced_receipt.receipt_id},
            )
            if nested_verdict is not None:
                return nested_verdict, max(max_depth, nested_depth + 1)
            max_depth = max(max_depth, nested_depth + 1)
        return None, max_depth

    def _load_intent(self, intent_id: str) -> ActionIntent | None:
        if self.intent_store is None:
            return None
        return self.intent_store.get_intent(intent_id)

    def _load_pccb(self, pccb_id: str) -> PCCB | None:
        if self.pccb_store is None:
            return None
        return self.pccb_store.get_pccb(pccb_id)

    def _list_receipts(self) -> tuple[Receipt, ...]:
        if self.receipt_store is None:
            return ()
        return self.receipt_store.list_receipts()

    def _list_refusals(self) -> tuple[Refusal, ...]:
        if self.refusal_store is None:
            return ()
        return self.refusal_store.list_refusals()

    def _list_pccbs(self) -> tuple[PCCB, ...]:
        if self.pccb_store is None:
            return ()
        return self.pccb_store.list_pccbs()

    def _prefer_receipt(self, receipts) -> Receipt | None:
        candidates = list(receipts)
        if not candidates:
            return None
        rank = {"executed": 0, "refused": 1, "allow": 2, "deny": 3, "approval-required": 4, "needs-evidence": 5}
        return sorted(candidates, key=lambda item: (rank.get(item.outcome, 99), item.occurred_at), reverse=False)[0]

    def _prefer_refusal(self, refusals) -> Refusal | None:
        candidates = list(refusals)
        if not candidates:
            return None
        return sorted(candidates, key=lambda item: item.refused_at)[0]

    def _prefer_pccb(self, pccbs) -> PCCB | None:
        candidates = list(pccbs)
        if not candidates:
            return None
        return sorted(candidates, key=lambda item: item.issued_at)[0]

    def _with_defaults(
        self,
        result: EvidenceResult,
        *,
        receipt: Receipt | None = None,
        refusal: Refusal | None = None,
        pccb: PCCB | None = None,
        intent: ActionIntent | None = None,
        chain_depth: int,
    ) -> EvidenceResult:
        return EvidenceResult(
            verdict=result.verdict,
            summary=result.summary,
            receipt_id=result.receipt_id or (receipt.receipt_id if receipt is not None else None),
            refusal_id=result.refusal_id or (refusal.refusal_id if refusal is not None else None),
            pccb_id=result.pccb_id or (pccb.pccb_id if pccb is not None else None),
            intent_id=result.intent_id or (intent.intent_id if intent is not None else None),
            action_hash=result.action_hash or (pccb.action_hash.value if pccb is not None else None),
            chain_depth=max(result.chain_depth, chain_depth),
            details=result.details,
        )

    def _result(
        self,
        verdict: EvidenceVerdict,
        summary: str,
        *,
        receipt_id: str | None = None,
        refusal_id: str | None = None,
        pccb_id: str | None = None,
        intent_id: str | None = None,
        action_hash: str | None = None,
        chain_depth: int = 0,
        details: dict[str, Any] | None = None,
    ) -> EvidenceResult:
        return EvidenceResult(
            verdict=verdict,
            summary=summary,
            receipt_id=receipt_id,
            refusal_id=refusal_id,
            pccb_id=pccb_id,
            intent_id=intent_id,
            action_hash=action_hash,
            chain_depth=chain_depth,
            details=details or {},
        )
