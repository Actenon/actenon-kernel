from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Protocol

from actenon.models.contracts import expect_mapping, expect_string, format_timestamp, parse_timestamp


EXTERNAL_ANCHOR_CONTRACT = {"name": "external_anchor", "version": "v1"}
LOCAL_APPEND_ONLY_ANCHOR_TYPE = "local_append_only_log"


class ExternalAnchorError(ValueError):
    """Base class for external anchor parsing and verification errors."""


class ExternalAnchorFormatError(ExternalAnchorError):
    """Raised when an external anchor has an unsupported wire shape."""


class ExternalAnchorVerificationError(ExternalAnchorError):
    """Raised when an external anchor does not verify against its local source."""


def normalize_artifact_digest(raw: Mapping[str, Any] | Any) -> dict[str, str]:
    data = expect_mapping(raw, "artifact_digest")
    normalized = {
        "algorithm": expect_string(data.get("algorithm"), "artifact_digest.algorithm"),
        "value": expect_string(data.get("value"), "artifact_digest.value"),
    }
    canonicalization = data.get("canonicalization")
    if canonicalization is not None:
        normalized["canonicalization"] = expect_string(
            canonicalization,
            "artifact_digest.canonicalization",
        )
    return normalized


def artifact_digests_match(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    left_digest = normalize_artifact_digest(left)
    right_digest = normalize_artifact_digest(right)
    if left_digest["algorithm"] != right_digest["algorithm"]:
        return False
    if left_digest["value"] != right_digest["value"]:
        return False
    left_canonicalization = left_digest.get("canonicalization")
    right_canonicalization = right_digest.get("canonicalization")
    if left_canonicalization is not None and right_canonicalization is not None:
        return left_canonicalization == right_canonicalization
    return True


def _parse_hash_spec(raw: Any, field_name: str) -> dict[str, str]:
    data = expect_mapping(raw, field_name)
    parsed = {
        "algorithm": expect_string(data.get("algorithm"), f"{field_name}.algorithm"),
        "value": expect_string(data.get("value"), f"{field_name}.value"),
    }
    canonicalization = data.get("canonicalization")
    if canonicalization is not None:
        parsed["canonicalization"] = expect_string(
            canonicalization,
            f"{field_name}.canonicalization",
        )
    return parsed


def _parse_positive_sequence(raw: Any) -> int:
    if not isinstance(raw, int) or raw <= 0:
        raise ExternalAnchorFormatError("external anchor sequence must be a positive integer")
    return raw


@dataclass(frozen=True)
class ExternalAnchor:
    anchor_id: str
    anchor_type: str
    artifact_digest: dict[str, str]
    anchored_at: datetime
    log_uri: str
    sequence: int
    entry_hash: dict[str, str]
    previous_entry_hash: dict[str, str] | None = None
    artifact_type: str | None = None
    artifact_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | Any) -> "ExternalAnchor":
        data = expect_mapping(raw, "external_anchor")
        contract = expect_mapping(data.get("contract"), "external_anchor.contract")
        if (
            contract.get("name") != EXTERNAL_ANCHOR_CONTRACT["name"]
            or contract.get("version") != EXTERNAL_ANCHOR_CONTRACT["version"]
        ):
            raise ExternalAnchorFormatError("external anchor contract must declare external_anchor v1")
        previous_entry_hash = data.get("previous_entry_hash")
        metadata = data.get("metadata", {})
        return cls(
            anchor_id=expect_string(data.get("anchor_id"), "external_anchor.anchor_id"),
            anchor_type=expect_string(data.get("anchor_type"), "external_anchor.anchor_type"),
            artifact_digest=normalize_artifact_digest(data.get("artifact_digest")),
            anchored_at=parse_timestamp(data.get("anchored_at"), "external_anchor.anchored_at"),
            log_uri=expect_string(data.get("log_uri"), "external_anchor.log_uri"),
            sequence=_parse_positive_sequence(data.get("sequence")),
            entry_hash=_parse_hash_spec(data.get("entry_hash"), "external_anchor.entry_hash"),
            previous_entry_hash=_parse_hash_spec(previous_entry_hash, "external_anchor.previous_entry_hash")
            if previous_entry_hash is not None
            else None,
            artifact_type=data.get("artifact_type") if isinstance(data.get("artifact_type"), str) else None,
            artifact_id=data.get("artifact_id") if isinstance(data.get("artifact_id"), str) else None,
            metadata=dict(expect_mapping(metadata, "external_anchor.metadata")) if metadata else {},
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": dict(EXTERNAL_ANCHOR_CONTRACT),
            "anchor_id": self.anchor_id,
            "anchor_type": self.anchor_type,
            "artifact_digest": dict(self.artifact_digest),
            "anchored_at": format_timestamp(self.anchored_at),
            "log_uri": self.log_uri,
            "sequence": self.sequence,
            "entry_hash": dict(self.entry_hash),
        }
        if self.previous_entry_hash is not None:
            payload["previous_entry_hash"] = dict(self.previous_entry_hash)
        if self.artifact_type is not None:
            payload["artifact_type"] = self.artifact_type
        if self.artifact_id is not None:
            payload["artifact_id"] = self.artifact_id
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass(frozen=True)
class AnchorVerificationResult:
    anchor: ExternalAnchor
    anchored_at: datetime
    status: str = "verified"


class ExternalAnchorVerifier(Protocol):
    def verify_external_anchor(
        self,
        anchor: ExternalAnchor | Mapping[str, Any],
        *,
        artifact_digest: Mapping[str, Any],
    ) -> AnchorVerificationResult:
        """Verify an external anchor against the expected signed artifact digest."""
