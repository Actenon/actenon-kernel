"""FastAPI dependency for proof-gated endpoint execution."""

from __future__ import annotations

import base64
import inspect
import json
from typing import Any, Callable, Mapping, Optional, Union

from actenon.core import ContractValidationError
from actenon.gate import ActenonGate, GateOutcome
from actenon.models import ActionIntent, PCCB
from actenon.preflight import PreflightEvidence

try:
    from fastapi import HTTPException, Request
    from pydantic import ValidationError
except ImportError as exc:  # pragma: no cover - exercised without the optional extra
    raise ImportError(
        "Actenon's FastAPI adapter requires the 'fastapi' extra: "
        "python -m pip install 'actenon-kernel[fastapi]'"
    ) from exc


ACTENON_PROOF_HEADER = "X-Actenon-Proof"
ACTENON_EVIDENCE_HEADER = "X-Actenon-Evidence"

ActionBuilder = Callable[[Mapping[str, Any]], Union[ActionIntent, dict[str, Any]]]
EvidenceBuilder = Callable[
    [Mapping[str, Any]],
    Optional[Union[Mapping[str, Any], PreflightEvidence]],
]
SideEffect = Callable[[Mapping[str, Any]], Any]


def encode_json_header(value: Mapping[str, Any] | PCCB) -> str:
    payload = value.to_dict() if isinstance(value, PCCB) else dict(value)
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return encoded.decode("ascii").rstrip("=")


def _decode_json_header(value: str, *, field_name: str) -> dict[str, Any]:
    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{field_name} must be base64url-encoded JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{field_name} must decode to a JSON object")
    return payload


def fastapi_dependency(
    gate: ActenonGate,
    *,
    action_builder: ActionBuilder,
    side_effect: SideEffect,
    body_model: type[Any] | None = None,
    audience: Optional[str] = None,
    evidence_builder: Optional[EvidenceBuilder] = None,
    proof_header: str = ACTENON_PROOF_HEADER,
    evidence_header: str = ACTENON_EVIDENCE_HEADER,
) -> Callable[[Request], Any]:
    """Build a dependency that executes the protected operation before the route.

    The HTTP body contains only domain fields. The proof and optional local
    evidence travel in base64url-encoded headers outside that domain schema.
    """

    if inspect.iscoroutinefunction(side_effect):
        raise TypeError(
            "fastapi_dependency currently requires a synchronous side_effect"
        )

    async def dependency(request: Request) -> GateOutcome:
        try:
            body = await request.json()
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": "INVALID_JSON_BODY", "message": str(exc)},
            ) from exc
        if not isinstance(body, dict):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "INVALID_JSON_BODY",
                    "message": "The protected endpoint body must be a JSON object.",
                },
            )
        if body_model is not None:
            try:
                if hasattr(body_model, "model_validate"):
                    validated = body_model.model_validate(body)
                    body = validated.model_dump()
                else:  # pragma: no cover - Pydantic v1 compatibility
                    validated = body_model.parse_obj(body)
                    body = validated.dict()
            except ValidationError as exc:
                raise HTTPException(status_code=422, detail=exc.errors()) from exc

        proof: dict[str, Any] | None = None
        raw_proof = request.headers.get(proof_header)
        if raw_proof:
            try:
                proof = _decode_json_header(raw_proof, field_name=proof_header)
            except ValueError:
                # Let the gate emit the canonical schema Refusal and refused Receipt.
                proof = {}

        if evidence_builder is not None:
            evidence = evidence_builder(body)
        else:
            evidence = None
            raw_evidence = request.headers.get(evidence_header)
            if raw_evidence:
                try:
                    evidence = _decode_json_header(
                        raw_evidence,
                        field_name=evidence_header,
                    )
                except ValueError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "INVALID_ACTENON_EVIDENCE",
                            "message": str(exc),
                        },
                    ) from exc

        try:
            action = action_builder(body)
        except (ContractValidationError, KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": "INVALID_ACTION", "message": str(exc)},
            ) from exc

        outcome = gate.protect(
            action,
            proof,
            lambda: side_effect(body),
            audience=audience,
            evidence=evidence,
        )
        if not outcome.ok:
            raise HTTPException(status_code=403, detail=outcome.to_dict())
        return outcome

    return dependency


__all__ = [
    "ACTENON_EVIDENCE_HEADER",
    "ACTENON_PROOF_HEADER",
    "encode_json_header",
    "fastapi_dependency",
]
