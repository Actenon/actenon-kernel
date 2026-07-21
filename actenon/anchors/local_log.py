from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from actenon.core.json import loads_no_duplicate_keys
from actenon.models.contracts import expect_mapping, format_timestamp, parse_timestamp, utc_now
from actenon.proof.canonical import sha256_hex

from .models import (
    EXTERNAL_ANCHOR_CONTRACT,
    LOCAL_APPEND_ONLY_ANCHOR_TYPE,
    AnchorVerificationResult,
    ExternalAnchor,
    ExternalAnchorFormatError,
    ExternalAnchorVerificationError,
    artifact_digests_match,
    normalize_artifact_digest,
)


LOCAL_ANCHOR_LOG_ENTRY_CONTRACT = {"name": "local_anchor_log_entry", "version": "v1"}
ENTRY_HASH_ALGORITHM = "sha-256"
from actenon.proof.canonical import CANONICALIZATION_PROFILE as ENTRY_HASH_CANONICALIZATION


def _hash_spec(value: Mapping[str, Any]) -> dict[str, str]:
    return {
        "algorithm": ENTRY_HASH_ALGORITHM,
        "canonicalization": ENTRY_HASH_CANONICALIZATION,
        "value": sha256_hex(dict(value)),
    }


def _entry_hash_payload(entry: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(entry)
    payload.pop("entry_hash", None)
    return payload


def _compute_entry_hash(entry: Mapping[str, Any]) -> dict[str, str]:
    return _hash_spec(_entry_hash_payload(entry))


def _entry_anchor(entry: Mapping[str, Any]) -> ExternalAnchor:
    return ExternalAnchor(
        anchor_id=str(entry["anchor_id"]),
        anchor_type=str(entry["anchor_type"]),
        artifact_digest=normalize_artifact_digest(entry["artifact_digest"]),
        anchored_at=parse_timestamp(entry["anchored_at"], "anchored_at"),
        log_uri=str(entry["log_uri"]),
        sequence=int(entry["sequence"]),
        entry_hash=dict(expect_mapping(entry["entry_hash"], "entry_hash")),
        previous_entry_hash=dict(expect_mapping(entry["previous_entry_hash"], "previous_entry_hash"))
        if entry.get("previous_entry_hash") is not None
        else None,
        artifact_type=entry.get("artifact_type") if isinstance(entry.get("artifact_type"), str) else None,
        artifact_id=entry.get("artifact_id") if isinstance(entry.get("artifact_id"), str) else None,
        metadata=dict(expect_mapping(entry.get("metadata"), "metadata")) if entry.get("metadata") else {},
    )


class LocalAppendOnlyAnchorLog:
    """JSONL hash-chain for local receipt/refusal durability anchors.

    The log is intentionally local-only. It provides an append-and-verify
    primitive for development, pilots, and single-node custody workflows. It is
    not a hosted trust network and does not prevent an operator with filesystem
    write access from deleting or replacing the whole file.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @property
    def log_uri(self) -> str:
        return self.path.expanduser().resolve().as_uri()

    def anchor_artifact_digest(
        self,
        artifact_digest: Mapping[str, Any],
        *,
        artifact_type: str | None = None,
        artifact_id: str | None = None,
        anchored_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ExternalAnchor:
        digest = normalize_artifact_digest(artifact_digest)
        existing_entries = self._read_entries(validate_chain=True)
        previous_hash = existing_entries[-1]["entry_hash"] if existing_entries else None
        sequence = len(existing_entries) + 1
        entry: dict[str, Any] = {
            "contract": dict(LOCAL_ANCHOR_LOG_ENTRY_CONTRACT),
            "anchor_contract": dict(EXTERNAL_ANCHOR_CONTRACT),
            "anchor_id": f"anc_local_{uuid4().hex}",
            "anchor_type": LOCAL_APPEND_ONLY_ANCHOR_TYPE,
            "artifact_digest": digest,
            "anchored_at": format_timestamp(anchored_at or utc_now()),
            "log_uri": self.log_uri,
            "sequence": sequence,
            "previous_entry_hash": previous_hash,
        }
        if artifact_type is not None:
            entry["artifact_type"] = artifact_type
        if artifact_id is not None:
            entry["artifact_id"] = artifact_id
        if metadata:
            entry["metadata"] = dict(metadata)
        entry["entry_hash"] = _compute_entry_hash(entry)
        self._append_entry(entry)
        return _entry_anchor(entry)

    def anchor_attestation(
        self,
        attestation: Any,
        *,
        anchored_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> ExternalAnchor:
        artifact_digest = getattr(attestation, "artifact_digest")
        artifact_type = getattr(attestation, "artifact_type", None)
        artifact_id = getattr(attestation, "artifact_id", None)
        return self.anchor_artifact_digest(
            artifact_digest,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            anchored_at=anchored_at,
            metadata=metadata,
        )

    def append_anchor_to_attestation(
        self,
        attestation: Any,
        *,
        anchored_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Any:
        anchor = self.anchor_attestation(
            attestation,
            anchored_at=anchored_at,
            metadata=metadata,
        )
        return replace(
            attestation,
            external_anchors=[*getattr(attestation, "external_anchors"), anchor.to_dict()],
        )

    def verify_external_anchor(
        self,
        anchor: ExternalAnchor | Mapping[str, Any],
        *,
        artifact_digest: Mapping[str, Any],
    ) -> AnchorVerificationResult:
        parsed_anchor = anchor if isinstance(anchor, ExternalAnchor) else ExternalAnchor.from_dict(anchor)
        if parsed_anchor.anchor_type != LOCAL_APPEND_ONLY_ANCHOR_TYPE:
            raise ExternalAnchorVerificationError(
                f"unsupported external anchor type {parsed_anchor.anchor_type!r}"
            )
        if parsed_anchor.log_uri != self.log_uri:
            raise ExternalAnchorVerificationError("external anchor points at a different local log")
        if not artifact_digests_match(parsed_anchor.artifact_digest, artifact_digest):
            raise ExternalAnchorVerificationError(
                "external anchor artifact_digest does not match the signed artifact_digest"
            )

        entries = self._read_entries(validate_chain=True)
        if parsed_anchor.sequence > len(entries):
            raise ExternalAnchorVerificationError("external anchor sequence is not present in the local log")
        entry = entries[parsed_anchor.sequence - 1]
        entry_anchor = _entry_anchor(entry)
        if entry_anchor != parsed_anchor:
            raise ExternalAnchorVerificationError("external anchor does not match the local log entry")
        return AnchorVerificationResult(anchor=parsed_anchor, anchored_at=parsed_anchor.anchored_at)

    def _append_entry(self, entry: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(entry), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
            handle.write("\n")

    def _read_entries(self, *, validate_chain: bool) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    entry = loads_no_duplicate_keys(stripped)
                except ValueError as exc:
                    raise ExternalAnchorFormatError(
                        f"local anchor log line {line_number} is not valid JSON"
                    ) from exc
                if not isinstance(entry, dict):
                    raise ExternalAnchorFormatError(
                        f"local anchor log line {line_number} must be a JSON object"
                    )
                entries.append(entry)
        if validate_chain:
            self._validate_chain(entries)
        return entries

    def _validate_chain(self, entries: list[dict[str, Any]]) -> None:
        previous_hash: dict[str, str] | None = None
        for index, entry in enumerate(entries, start=1):
            contract = entry.get("contract")
            if contract != LOCAL_ANCHOR_LOG_ENTRY_CONTRACT:
                raise ExternalAnchorFormatError("local anchor log entry contract is unsupported")
            if entry.get("anchor_type") != LOCAL_APPEND_ONLY_ANCHOR_TYPE:
                raise ExternalAnchorFormatError("local anchor log entry anchor_type is unsupported")
            if entry.get("sequence") != index:
                raise ExternalAnchorFormatError("local anchor log sequence is not contiguous")
            if entry.get("previous_entry_hash") != previous_hash:
                raise ExternalAnchorVerificationError("local anchor log hash chain is broken")
            expected_hash = _compute_entry_hash(entry)
            if entry.get("entry_hash") != expected_hash:
                raise ExternalAnchorVerificationError("local anchor log entry hash does not match")
            previous_hash = expected_hash
