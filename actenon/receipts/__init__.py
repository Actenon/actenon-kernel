"""Receipt and refusal generation plus persistence hooks."""

from .attestation import (
    ATTESTATION_CANONICALIZATION,
    ATTESTATION_DIGEST_ALGORITHM,
    OutcomeAttestationError,
    OutcomeAttestationService,
    OutcomeAttestationVerificationError,
    ReceiptAttestationV2Alpha1,
    RefusalAttestationV2Alpha1,
)
from .factory import ReceiptFactory, RefusalFactory
from .invoice_payment import is_invoice_payment_intent
from .refund import is_refund_intent
from .store import (
    InMemoryReceiptStore,
    InMemoryRefusalStore,
    JsonArtifactReceiptStore,
    JsonArtifactRefusalStore,
    ReceiptStore,
    RefusalStore,
)
from .writers import CompositeOutcomeWriter, InMemoryOutcomeWriter, JsonArtifactOutcomeWriter, OutcomeWriter

__all__ = [
    "ATTESTATION_CANONICALIZATION",
    "ATTESTATION_DIGEST_ALGORITHM",
    "CompositeOutcomeWriter",
    "InMemoryOutcomeWriter",
    "is_invoice_payment_intent",
    "is_refund_intent",
    "JsonArtifactOutcomeWriter",
    "JsonArtifactReceiptStore",
    "JsonArtifactRefusalStore",
    "InMemoryReceiptStore",
    "InMemoryRefusalStore",
    "OutcomeAttestationError",
    "OutcomeAttestationService",
    "OutcomeAttestationVerificationError",
    "OutcomeWriter",
    "ReceiptFactory",
    "ReceiptStore",
    "ReceiptAttestationV2Alpha1",
    "RefusalFactory",
    "RefusalStore",
    "RefusalAttestationV2Alpha1",
]
