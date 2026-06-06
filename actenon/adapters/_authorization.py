from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from actenon.models import PCCB
from actenon.preflight import PreflightEvidence


@dataclass(frozen=True)
class AdapterAuthorization:
    """Proof material supplied by framework runtime context, never model input."""

    proof: Mapping[str, Any] | PCCB | None
    evidence: Mapping[str, Any] | PreflightEvidence | None = None


def authorization_from_mapping(raw: Any) -> AdapterAuthorization:
    if not isinstance(raw, Mapping):
        return AdapterAuthorization(proof=None)
    evidence = raw.get("evidence")
    if evidence is not None and not isinstance(
        evidence,
        (Mapping, PreflightEvidence),
    ):
        evidence = None
    return AdapterAuthorization(
        proof=raw.get("proof"),
        evidence=evidence,
    )
