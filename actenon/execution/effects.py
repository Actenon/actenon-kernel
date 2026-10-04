"""Independent effect ownership verification at a protected execution edge.

The ledger is supplied by the authority engine. This module neither issues
policy nor reserves budget. A proof reference is not an execution claim.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from actenon_protocol import parse_authority_extension
from actenon_protocol.effects import EFFECT_PROFILE, effect_identity

from actenon.core.errors import ProofVerificationError
from actenon.models.runtime import ProtectedExecutionRequest
from actenon.proof.canonical import canonicalize_bytes


@dataclass(frozen=True)
class EffectReference:
    """Protocol effect_reference.v1, parsed without optional model dependencies."""

    profile: str
    effect_id: str
    reservation_id: str
    owner_attempt_id: str

    @classmethod
    def from_dict(cls, raw: Any) -> EffectReference:
        patterns = {
            "effect_id": r"effect_[0-9a-f]{64}",
            "reservation_id": r"reservation_[0-9a-f]{32}",
            "owner_attempt_id": r"exec_[0-9a-f]{16,}",
        }
        if not isinstance(raw, Mapping) or set(raw) != {"profile", *patterns}:
            raise ValueError("malformed effect reference")
        if raw["profile"] != EFFECT_PROFILE:
            raise ValueError("unsupported effect profile")
        for name, pattern in patterns.items():
            if (
                not isinstance(raw[name], str)
                or re.fullmatch(pattern, raw[name]) is None
            ):
                raise ValueError("malformed effect reference")
        return cls(**raw)

    def to_dict(self) -> dict[str, str]:
        return {
            "profile": self.profile,
            "effect_id": self.effect_id,
            "reservation_id": self.reservation_id,
            "owner_attempt_id": self.owner_attempt_id,
        }


EffectClaim = Callable[[EffectReference, ProtectedExecutionRequest], bool]
EffectDescriptorBuilder = Callable[[ProtectedExecutionRequest], Mapping[str, Any]]


@dataclass(frozen=True)
class EffectProtector:
    """Recompute identity, then atomically claim the exact signed reservation.

    ``namespace`` belongs to the resource owner, never the calling agent.
    ``claim`` must atomically verify grant/principal/action-hash/reference and
    transition RESERVED -> DISPATCHING in the authoritative ledger. It may
    return True once only. Exceptions, absent ownership, and false results
    refuse before credential acquisition or handler execution.

    An optional semantic descriptor builder is trusted edge configuration;
    it is not an agent-supplied nonce. Its namespace/action/target are checked
    independently here. It must derive the reviewed semantic key from the
    actual execution request. Exact descriptors must include every parameter.

    Claiming is deliberately irreversible here: a crash after claim keeps the
    effect held until trusted boundary/operator reconciliation. This class
    does not infer COMMITTED from a handler return or HTTP status.
    """

    namespace: str
    claim: EffectClaim
    descriptor_builder: EffectDescriptorBuilder | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.namespace, str)
            or not self.namespace
            or self.namespace.strip() != self.namespace
        ):
            raise ValueError("effect namespace must be owner configured")
        if not callable(self.claim):
            raise ValueError("effect protection requires an atomic ledger claim")

    def claim_request(self, request: ProtectedExecutionRequest) -> EffectReference:
        try:
            reference = EffectReference.from_dict(request.pccb.extensions.get("effect"))
            authority = parse_authority_extension(request.pccb.extensions)
        except (TypeError, ValueError) as exc:
            raise ProofVerificationError(
                "MALFORMED_REQUEST",
                "The proof has no usable effect/authority reference.",
            ) from exc
        if reference.owner_attempt_id != request.intent.intent_id:
            raise ProofVerificationError(
                "ACTION_MISMATCH",
                "The effect reservation belongs to a different execution attempt.",
            )
        if (
            authority["issuer"]
            != f"{request.pccb.issuer.type}:{request.pccb.issuer.id}"
        ):
            raise ProofVerificationError(
                "ISSUER_UNTRUSTED",
                "The effect authority issuer does not match the proof issuer.",
            )
        expected = {
            "profile": EFFECT_PROFILE,
            "namespace": self.namespace,
            "kind": "exact",
            "action_type": request.intent.action.capability,
            "target": {
                "type": request.intent.target.resource_type,
                "id": request.intent.target.resource_id,
            },
            "parameters": copy.deepcopy(request.intent.action.parameters),
        }
        try:
            descriptor = (
                dict(self.descriptor_builder(request))
                if self.descriptor_builder is not None
                else expected
            )
            for name in ("profile", "namespace", "action_type", "target"):
                if canonicalize_bytes(descriptor.get(name)) != canonicalize_bytes(
                    expected[name]
                ):
                    raise ValueError(
                        "effect descriptor does not match the actual edge request"
                    )
            if descriptor.get("kind") == "exact" and canonicalize_bytes(
                descriptor.get("parameters")
            ) != canonicalize_bytes(expected["parameters"]):
                raise ValueError(
                    "exact effect descriptor dropped or changed parameters"
                )
            computed = effect_identity(descriptor)
        except Exception as exc:
            raise ProofVerificationError(
                "ACTION_MISMATCH",
                "The protected edge could not derive this effect from the exact request.",
            ) from exc
        if reference.effect_id != computed:
            raise ProofVerificationError(
                "ACTION_MISMATCH",
                "The signed effect identity does not match the protected request.",
            )
        try:
            claimed = self.claim(reference, request)
        except Exception as exc:
            raise ProofVerificationError(
                "POLICY_REFUSAL",
                "Authoritative effect ownership could not be established; execution refused.",
            ) from exc
        if claimed is not True:
            raise ProofVerificationError(
                "POLICY_REFUSAL",
                "This effect is already owned, completed, unresolved, or not authorized for this attempt.",
            )
        return reference
