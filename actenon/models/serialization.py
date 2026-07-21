from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from actenon.proof.canonical import canonicalize_bytes, canonicalize_json, sha256_hex

from .contracts import DigestSpec


ARTIFACT_HASH_ALGORITHM = "sha-256"
from actenon.proof.canonical import CANONICALIZATION_PROFILE as ARTIFACT_HASH_CANONICALIZATION


class ArtifactLike(Protocol):
    def to_dict(self) -> dict[str, Any]:
        ...


def artifact_payload(value: ArtifactLike | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    payload = value.to_dict()
    if not isinstance(payload, Mapping):
        raise TypeError("artifact to_dict() must return a mapping")
    return dict(payload)


def canonicalize_artifact_json(value: ArtifactLike | Mapping[str, Any]) -> str:
    return canonicalize_json(artifact_payload(value))


def canonicalize_artifact_bytes(value: ArtifactLike | Mapping[str, Any]) -> bytes:
    return canonicalize_bytes(artifact_payload(value))


def sha256_artifact_hex(value: ArtifactLike | Mapping[str, Any]) -> str:
    return sha256_hex(artifact_payload(value))


def build_artifact_digest(value: ArtifactLike | Mapping[str, Any]) -> DigestSpec:
    return DigestSpec(
        algorithm=ARTIFACT_HASH_ALGORITHM,
        canonicalization=ARTIFACT_HASH_CANONICALIZATION,
        value=sha256_artifact_hex(value),
    )
