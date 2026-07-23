from __future__ import annotations

import json
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any, Protocol

from actenon.models.contracts import PCCB, format_timestamp

from .canonical import sha256_hex


def _digest(value: Any) -> dict[str, str]:
    return {"algorithm": "sha-256", "value": sha256_hex(value)}


def _party_minimal(value) -> dict[str, str]:
    return {"type": value.type, "id": value.id}


@dataclass(frozen=True)
class PCCBMintAuditRecord:
    """Privacy-conscious correlation record for a PCCB mint event.

    The record intentionally avoids action parameters, tenant identifiers,
    subject identifiers, target resource identifiers, and signature bytes.
    """

    pccb: PCCB

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "pccb_mint_audit_record", "version": "v1"},
            "event_type": "pccb_minted",
            "pccb_id": self.pccb.pccb_id,
            "intent_id": self.pccb.intent_id,
            "issued_at": format_timestamp(self.pccb.issued_at),
            "not_before": format_timestamp(self.pccb.not_before),
            "expires_at": format_timestamp(self.pccb.expires_at),
            "issuer": _party_minimal(self.pccb.issuer),
            "audience": _party_minimal(self.pccb.audience),
            "tenant_digest": _digest(self.pccb.tenant.to_dict()),
            "subject_digest": _digest(self.pccb.subject.to_dict()),
            "action": {
                "name": self.pccb.action.name,
                "capability": self.pccb.action.capability,
            },
            "target": {
                "resource_type": self.pccb.target.resource_type,
                "resource_digest": _digest(self.pccb.target.to_dict()),
            },
            "scope": {
                "mode": self.pccb.scope.mode,
                "capabilities": tuple(sorted(self.pccb.scope.capabilities)),
                "single_use": self.pccb.scope.single_use,
            },
            "action_hash": self.pccb.action_hash.to_dict(),
            "nonce_digest": _digest(self.pccb.nonce),
            "signature": {
                "algorithm": self.pccb.signature.algorithm,
                "key_id": self.pccb.signature.key_id,
                "encoding": self.pccb.signature.encoding,
            },
        }
        if self.pccb.escrow_id is not None:
            payload["escrow_id"] = self.pccb.escrow_id
        return payload


class AuditLogSink(Protocol):
    def record_pccb_mint(self, record: PCCBMintAuditRecord) -> None:
        """Persist or forward a PCCB mint audit record."""


@dataclass(frozen=True)
class LocalAppendOnlyAuditLogSink:
    """Append PCCB mint audit records to a local JSONL file."""

    path: str | PathLike[str]

    def record_pccb_mint(self, record: PCCBMintAuditRecord) -> None:
        target = Path(self.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            json.dump(record.to_dict(), handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
