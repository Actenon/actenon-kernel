"""Hardened resource-side adapter for exact-request proof enforcement."""

from __future__ import annotations

import copy
import inspect
from typing import Any, Callable, Mapping, Union

from actenon.credentials import BrokeredCredential
from actenon.gate import ActenonGate, GateOutcome
from actenon.models import ActionIntent, AudienceRef, PCCB
from actenon.preflight import PreflightEvidence
from actenon.proof import canonicalize_json


RawRequestedAction = Mapping[str, Any]
IntentBuilder = Callable[
    [RawRequestedAction],
    Union[ActionIntent, dict[str, Any]],
]
BrokeredBackend = Callable[[ActionIntent, BrokeredCredential], Any]


class EdgeConfigurationError(ValueError):
    """Raised when an edge cannot bind every requested field into its intent."""


class ProtectedEdge:
    """Verify an agent request before a brokered resource-side side effect.

    The raw request is snapshotted and must appear exactly in
    ``ActionIntent.action.parameters``. The backend receives only the verified
    request intent and a brokered credential; it never receives the PCCB or an
    action reconstructed from proof contents.
    """

    def __init__(
        self,
        gate: ActenonGate,
        *,
        intent_builder: IntentBuilder,
        backend: BrokeredBackend,
        audience: AudienceRef | str | None = None,
    ) -> None:
        if not isinstance(gate, ActenonGate):
            raise TypeError("gate must be an ActenonGate")
        if not callable(intent_builder):
            raise TypeError("intent_builder must be callable")
        if not callable(backend):
            raise TypeError("backend must be callable")
        if inspect.iscoroutinefunction(intent_builder):
            raise TypeError("ProtectedEdge currently requires a synchronous intent_builder")
        if inspect.iscoroutinefunction(backend):
            raise TypeError("ProtectedEdge currently requires a synchronous backend")
        self._gate = gate
        self._intent_builder = intent_builder
        self._backend = backend
        self._audience = audience

    def intent_for(self, requested_action: RawRequestedAction) -> ActionIntent:
        """Build a detached Action Intent that binds the complete raw request."""

        if isinstance(requested_action, ActionIntent) or not isinstance(
            requested_action, Mapping
        ):
            raise TypeError("requested_action must be a raw mapping, not an ActionIntent")
        request_snapshot = copy.deepcopy(dict(requested_action))
        try:
            request_canonical = canonicalize_json(request_snapshot)
        except (TypeError, ValueError, RecursionError) as exc:
            raise EdgeConfigurationError(
                "requested_action must be valid canonical JSON data"
            ) from exc

        built = self._intent_builder(copy.deepcopy(request_snapshot))
        try:
            intent = (
                ActionIntent.from_dict(built.to_dict())
                if isinstance(built, ActionIntent)
                else ActionIntent.from_dict(built)
            )
        except (TypeError, ValueError) as exc:
            raise EdgeConfigurationError(
                "intent_builder must return a valid ActionIntent or Action Intent mapping"
            ) from exc

        try:
            bound_parameters = canonicalize_json(intent.action.parameters)
        except (TypeError, ValueError, RecursionError) as exc:
            raise EdgeConfigurationError(
                "intent_builder produced action parameters that are not canonical JSON"
            ) from exc
        if bound_parameters != request_canonical:
            raise EdgeConfigurationError(
                "intent_builder must bind the complete raw requested action exactly "
                "as ActionIntent.action.parameters"
            )
        return intent

    def execute(
        self,
        requested_action: RawRequestedAction,
        proof: Mapping[str, Any] | PCCB | None,
        *,
        evidence: Mapping[str, Any] | PreflightEvidence | None = None,
    ) -> GateOutcome:
        """Execute only the raw request proven by the supplied PCCB."""

        intent = self.intent_for(requested_action)
        return self._gate.protect(
            intent,
            proof,
            lambda protected_request, credential: self._backend(
                protected_request.intent,
                credential,
            ),
            audience=self._audience,
            evidence=evidence,
            _missing_proof_reason_code="NO_PROOF",
        )


__all__ = [
    "BrokeredBackend",
    "EdgeConfigurationError",
    "IntentBuilder",
    "ProtectedEdge",
    "RawRequestedAction",
]
