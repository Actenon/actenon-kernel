from __future__ import annotations

from dataclasses import replace
from threading import Lock

from .base import CapabilityEscrow, EscrowRecord


def _escrow_error(refusal_code: str, message: str) -> Exception:
    from actenon.core.errors import EscrowValidationError

    return EscrowValidationError(refusal_code, message)


class InMemoryCapabilityEscrow(CapabilityEscrow):
    def __init__(self) -> None:
        self._records: dict[str, EscrowRecord] = {}
        self._lock = Lock()

    def issue(self, *, escrow_id: str, pccb_id: str, capability: str, expires_at, metadata=None) -> EscrowRecord:
        with self._lock:
            if escrow_id in self._records:
                raise _escrow_error("ESCROW_ALREADY_EXISTS", "The escrow record already exists.")
            record = EscrowRecord(
                escrow_id=escrow_id,
                pccb_id=pccb_id,
                capability=capability,
                expires_at=expires_at,
                metadata=dict(metadata or {}),
            )
            self._records[escrow_id] = record
            return record

    def inspect(self, escrow_id: str) -> EscrowRecord | None:
        return self._records.get(escrow_id)

    def consume(self, *, escrow_id: str, pccb_id: str, capability: str, now) -> EscrowRecord:
        with self._lock:
            record = self._records.get(escrow_id)
            if record is None:
                raise _escrow_error("ESCROW_NOT_FOUND", "The escrow record does not exist.")
            if record.state == "revoked":
                raise _escrow_error("ESCROW_REVOKED", "The escrow record has been revoked.")
            if record.state == "consumed":
                raise _escrow_error("ESCROW_ALREADY_CONSUMED", "The escrow record has already been consumed.")
            if now > record.expires_at:
                expired = replace(record, state="expired")
                self._records[escrow_id] = expired
                raise _escrow_error("ESCROW_EXPIRED", "The escrow record has expired.")
            if record.pccb_id != pccb_id:
                raise _escrow_error("ESCROW_PCCB_MISMATCH", "The escrow record does not match the proof.")
            if record.capability != capability:
                raise _escrow_error("ESCROW_CAPABILITY_MISMATCH", "The escrow record does not match the requested capability.")
            consumed = replace(record, state="consumed", consumed_at=now)
            self._records[escrow_id] = consumed
            return consumed

    def revoke(self, escrow_id: str, *, reason: str) -> EscrowRecord:
        with self._lock:
            record = self._records.get(escrow_id)
            if record is None:
                raise _escrow_error("ESCROW_NOT_FOUND", "The escrow record does not exist.")
            revoked = replace(record, state="revoked", metadata={**record.metadata, "revocation_reason": reason})
            self._records[escrow_id] = revoked
            return revoked
