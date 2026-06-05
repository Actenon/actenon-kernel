from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from actenon.core.json import loads_no_duplicate_keys
from actenon.core.errors import RefusalException
from actenon.models.contracts import ActionIntent, PCCB, format_timestamp
from actenon.models.runtime import DynamicContextInput, PolicyDecision, RuleEvaluation


ProofSealTransport = Callable[[str, bytes, float], bytes]


class ProofSealError(RefusalException):
    """Raised when optional proof sealing cannot produce a usable PCCB."""

    def __init__(
        self,
        refusal_code: str,
        message: str,
        *,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            category="proof",
            refusal_code=refusal_code,
            message=message,
            retryable=retryable,
            details=details or {},
        )


class ProofSealClient(Protocol):
    """Optional client hook for substituting a sealed PCCB on the admit path.

    This hook is intentionally synchronous. If a deployer enables proof sealing,
    the returned PCCB may replace the locally minted PCCB used for subsequent
    escrow issuance and protected-endpoint execution. That means proof sealing
    is not a fire-and-forget publication path.
    """

    def seal(
        self,
        *,
        intent: ActionIntent,
        decision: PolicyDecision,
        context: DynamicContextInput,
        pccb: PCCB,
    ) -> PCCB:
        """Return the PCCB the kernel should use for subsequent execution."""


@dataclass(frozen=True)
class NoOpProofSealClient:
    """Proof-seal client that preserves existing local PCCB behavior."""

    def seal(
        self,
        *,
        intent: ActionIntent,
        decision: PolicyDecision,
        context: DynamicContextInput,
        pccb: PCCB,
    ) -> PCCB:
        return pccb


def _default_post_json(endpoint_url: str, payload: bytes, timeout_seconds: float) -> bytes:
    request = Request(
        endpoint_url,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return response.read()
    except HTTPError as exc:
        raise ProofSealError(
            "PROOF_SEAL_FAILED",
            f"proof seal service rejected the request with HTTP {exc.code}.",
            retryable=500 <= exc.code < 600,
            details={"status_code": exc.code},
        ) from exc
    except URLError as exc:
        raise ProofSealError(
            "PROOF_SEAL_FAILED",
            "proof seal service could not be reached.",
            retryable=True,
            details={"reason": str(exc.reason)},
        ) from exc


def _rule_evaluation_payload(item: RuleEvaluation) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": item.rule_id,
        "outcome": item.outcome,
        "reason_code": item.reason_code,
        "summary": item.summary,
    }
    if item.details:
        payload["details"] = item.details
    if item.required_evidence:
        payload["required_evidence"] = list(item.required_evidence)
    if item.approver_types:
        payload["approver_types"] = list(item.approver_types)
    return payload


def _decision_payload(decision: PolicyDecision) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "outcome": decision.outcome,
        "summary": decision.summary,
        "rule_evaluations": [_rule_evaluation_payload(item) for item in decision.rule_evaluations],
    }
    if decision.reason_codes:
        payload["reason_codes"] = list(decision.reason_codes)
    if decision.required_evidence:
        payload["required_evidence"] = list(decision.required_evidence)
    if decision.approver_types:
        payload["approver_types"] = list(decision.approver_types)
    return payload


def _context_payload(context: DynamicContextInput) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": context.request_id,
        "audience": context.audience.to_dict(),
        "scope_capabilities": list(context.scope_capabilities),
        "now": format_timestamp(context.now),
    }
    if context.facts:
        payload["facts"] = context.facts
    if context.parameter_constraints:
        payload["parameter_constraints"] = context.parameter_constraints
    if context.resource_selectors:
        payload["resource_selectors"] = list(context.resource_selectors)
    if context.required_evidence_types:
        payload["required_evidence_types"] = list(context.required_evidence_types)
    if context.approver_types:
        payload["approver_types"] = list(context.approver_types)
    if context.max_ttl_seconds is not None:
        payload["max_ttl_seconds"] = context.max_ttl_seconds
    return payload


def build_proof_seal_request(
    *,
    intent: ActionIntent,
    decision: PolicyDecision,
    context: DynamicContextInput,
    pccb: PCCB,
) -> dict[str, Any]:
    """Build the reference JSON body for an optional proof-seal HTTP client."""

    return {
        "intent": intent.to_dict(),
        "decision": _decision_payload(decision),
        "context": _context_payload(context),
        "pccb": pccb.to_dict(),
    }


@dataclass
class HttpProofSealClient:
    """Optional stdlib-only HTTP client for external proof-seal substitution.

    This client is a transport stub, not a hosted protocol claim. It sends the
    locally minted PCCB plus local decision context to a configured endpoint and
    expects a JSON response with a top-level `pccb` object that can replace the
    local PCCB for subsequent execution.
    """

    endpoint_url: str
    timeout_seconds: float = 5.0
    transport: ProofSealTransport = _default_post_json

    def seal(
        self,
        *,
        intent: ActionIntent,
        decision: PolicyDecision,
        context: DynamicContextInput,
        pccb: PCCB,
    ) -> PCCB:
        request_payload = build_proof_seal_request(
            intent=intent,
            decision=decision,
            context=context,
            pccb=pccb,
        )
        body = json.dumps(request_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        response_body = self.transport(self.endpoint_url, body, self.timeout_seconds)
        try:
            response_payload = loads_no_duplicate_keys(response_body)
        except ValueError as exc:
            raise ProofSealError(
                "PROOF_SEAL_FAILED",
                "proof seal service returned invalid JSON.",
            ) from exc
        if not isinstance(response_payload, Mapping):
            raise ProofSealError("PROOF_SEAL_FAILED", "proof seal service returned an invalid response body.")
        raw_pccb = response_payload.get("pccb")
        if not isinstance(raw_pccb, Mapping):
            raise ProofSealError("PROOF_SEAL_FAILED", "proof seal service response did not include a PCCB.")
        try:
            return PCCB.from_dict(raw_pccb)
        except Exception as exc:
            raise ProofSealError(
                "PROOF_SEAL_FAILED",
                "proof seal service returned a malformed PCCB.",
            ) from exc
