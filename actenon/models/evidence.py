from __future__ import annotations

from actenon.models.contracts import EvidenceRef, Receipt
from actenon.models.serialization import build_artifact_digest


EVIDENCE_TYPE_RECEIPT = "actenon.receipt"


def receipt_evidence_ref(receipt: Receipt) -> EvidenceRef:
    return EvidenceRef(
        type=EVIDENCE_TYPE_RECEIPT,
        value=receipt.receipt_id,
        digest=build_artifact_digest(receipt).to_dict(),
    )
