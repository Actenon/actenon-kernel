from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Union


JsonScalar = Union[str, int, float, bool, None]
JsonValue = Union[JsonScalar, dict[str, Any], list[Any]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(raw: Any, field_name: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be an RFC3339 timestamp string")
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an RFC3339 timestamp string") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include timezone information")
    return parsed.astimezone(timezone.utc)


def expect_mapping(raw: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{field_name} must be an object")
    return raw


def expect_string(raw: Any, field_name: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field_name} must be a non-empty string")
    return raw


def expect_bool(raw: Any, field_name: str) -> bool:
    if not isinstance(raw, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return raw


def expect_json_scalar(raw: Any, field_name: str) -> JsonScalar:
    if raw is None or isinstance(raw, (str, int, float, bool)):
        return raw
    raise ValueError(f"{field_name} must be a JSON scalar")


@dataclass(frozen=True)
class TenantRef:
    tenant_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "TenantRef":
        data = expect_mapping(raw, "tenant")
        return cls(
            tenant_id=expect_string(data.get("tenant_id"), "tenant.tenant_id"),
            attributes=dict(data.get("attributes", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"tenant_id": self.tenant_id}
        if self.attributes:
            payload["attributes"] = self.attributes
        return payload


@dataclass(frozen=True)
class PartyRef:
    type: str
    id: str
    display_name: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any, field_name: str) -> "PartyRef":
        data = expect_mapping(raw, field_name)
        return cls(
            type=expect_string(data.get("type"), f"{field_name}.type"),
            id=expect_string(data.get("id"), f"{field_name}.id"),
            display_name=data.get("display_name"),
            attributes=dict(data.get("attributes", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": self.type, "id": self.id}
        if self.display_name is not None:
            payload["display_name"] = self.display_name
        if self.attributes:
            payload["attributes"] = self.attributes
        return payload


@dataclass(frozen=True)
class AudienceRef:
    type: str
    id: str
    uri: str | None = None

    @classmethod
    def from_dict(cls, raw: Any, field_name: str = "audience") -> "AudienceRef":
        data = expect_mapping(raw, field_name)
        return cls(
            type=expect_string(data.get("type"), f"{field_name}.type"),
            id=expect_string(data.get("id"), f"{field_name}.id"),
            uri=data.get("uri"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": self.type, "id": self.id}
        if self.uri is not None:
            payload["uri"] = self.uri
        return payload


@dataclass(frozen=True)
class ActionSpec:
    name: str
    capability: str
    parameters: dict[str, Any]
    constraints: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "ActionSpec":
        data = expect_mapping(raw, "action")
        return cls(
            name=expect_string(data.get("name"), "action.name"),
            capability=expect_string(data.get("capability"), "action.capability"),
            parameters=dict(expect_mapping(data.get("parameters"), "action.parameters")),
            constraints=dict(data.get("constraints", {})),
            scope=dict(data.get("scope", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "capability": self.capability,
            "parameters": self.parameters,
        }
        if self.constraints:
            payload["constraints"] = self.constraints
        if self.scope:
            payload["scope"] = self.scope
        return payload


@dataclass(frozen=True)
class TargetRef:
    resource_type: str
    resource_id: str
    uri: str | None = None
    selectors: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "TargetRef":
        data = expect_mapping(raw, "target")
        return cls(
            resource_type=expect_string(data.get("resource_type"), "target.resource_type"),
            resource_id=expect_string(data.get("resource_id"), "target.resource_id"),
            uri=data.get("uri"),
            selectors=dict(data.get("selectors", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
        }
        if self.uri is not None:
            payload["uri"] = self.uri
        if self.selectors:
            payload["selectors"] = self.selectors
        return payload


@dataclass(frozen=True)
class EvidenceRef:
    type: str
    value: str
    digest: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "EvidenceRef":
        data = expect_mapping(raw, "evidence_ref")
        return cls(
            type=expect_string(data.get("type"), "evidence_ref.type"),
            value=expect_string(data.get("value"), "evidence_ref.value"),
            digest=dict(data.get("digest", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": self.type, "value": self.value}
        if self.digest:
            payload["digest"] = self.digest
        return payload


@dataclass(frozen=True)
class ScopeSpec:
    mode: str
    capabilities: tuple[str, ...]
    single_use: bool
    resource_selectors: tuple[dict[str, Any], ...] = ()
    parameter_constraints: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Any) -> "ScopeSpec":
        data = expect_mapping(raw, "scope")
        raw_capabilities = data.get("capabilities")
        if not isinstance(raw_capabilities, list) or not raw_capabilities:
            raise ValueError("scope.capabilities must be a non-empty array")
        capabilities = tuple(expect_string(item, "scope.capabilities[]") for item in raw_capabilities)
        selectors = tuple(dict(expect_mapping(item, "scope.resource_selectors[]")) for item in data.get("resource_selectors", []))
        return cls(
            mode=expect_string(data.get("mode"), "scope.mode"),
            capabilities=capabilities,
            single_use=expect_bool(data.get("single_use"), "scope.single_use"),
            resource_selectors=selectors,
            parameter_constraints=dict(data.get("parameter_constraints", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "mode": self.mode,
            "capabilities": list(self.capabilities),
            "single_use": self.single_use,
        }
        if self.resource_selectors:
            payload["resource_selectors"] = list(self.resource_selectors)
        if self.parameter_constraints:
            payload["parameter_constraints"] = self.parameter_constraints
        return payload


@dataclass(frozen=True)
class ActionHashSpec:
    algorithm: str
    canonicalization: str
    value: str

    @classmethod
    def from_dict(cls, raw: Any, field_name: str = "action_hash") -> "ActionHashSpec":
        data = expect_mapping(raw, field_name)
        return cls(
            algorithm=expect_string(data.get("algorithm"), f"{field_name}.algorithm"),
            canonicalization=expect_string(data.get("canonicalization"), f"{field_name}.canonicalization"),
            value=expect_string(data.get("value"), f"{field_name}.value"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "value": self.value,
        }


@dataclass(frozen=True)
class DigestSpec:
    algorithm: str
    canonicalization: str
    value: str

    @classmethod
    def from_dict(cls, raw: Any, field_name: str = "artifact_digest") -> "DigestSpec":
        data = expect_mapping(raw, field_name)
        return cls(
            algorithm=expect_string(data.get("algorithm"), f"{field_name}.algorithm"),
            canonicalization=expect_string(data.get("canonicalization"), f"{field_name}.canonicalization"),
            value=expect_string(data.get("value"), f"{field_name}.value"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "value": self.value,
        }


@dataclass(frozen=True)
class SignatureSpec:
    algorithm: str
    key_id: str
    encoding: str
    value: str

    @classmethod
    def from_dict(cls, raw: Any) -> "SignatureSpec":
        data = expect_mapping(raw, "signature")
        return cls(
            algorithm=expect_string(data.get("algorithm"), "signature.algorithm"),
            key_id=expect_string(data.get("key_id"), "signature.key_id"),
            encoding=expect_string(data.get("encoding"), "signature.encoding"),
            value=expect_string(data.get("value"), "signature.value"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "encoding": self.encoding,
            "value": self.value,
        }


@dataclass(frozen=True)
class CorrelationRef:
    pccb_id: str | None = None
    escrow_id: str | None = None
    refusal_id: str | None = None
    receipt_id: str | None = None
    request_id: str | None = None
    action_hash: ActionHashSpec | None = None

    @classmethod
    def from_dict(cls, raw: Any) -> "CorrelationRef":
        data = expect_mapping(raw, "correlation")
        action_hash = data.get("action_hash")
        return cls(
            pccb_id=data.get("pccb_id"),
            escrow_id=data.get("escrow_id"),
            refusal_id=data.get("refusal_id"),
            receipt_id=data.get("receipt_id"),
            request_id=data.get("request_id"),
            action_hash=ActionHashSpec.from_dict(action_hash, "correlation.action_hash") if action_hash else None,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.pccb_id is not None:
            payload["pccb_id"] = self.pccb_id
        if self.escrow_id is not None:
            payload["escrow_id"] = self.escrow_id
        if self.refusal_id is not None:
            payload["refusal_id"] = self.refusal_id
        if self.receipt_id is not None:
            payload["receipt_id"] = self.receipt_id
        if self.request_id is not None:
            payload["request_id"] = self.request_id
        if self.action_hash is not None:
            payload["action_hash"] = self.action_hash.to_dict()
        return payload


@dataclass(frozen=True)
class Violation:
    code: str
    message: str
    field_path: str | None = None
    expected: JsonScalar = None
    observed: JsonScalar = None

    @classmethod
    def from_dict(cls, raw: Any) -> "Violation":
        data = expect_mapping(raw, "violation")
        return cls(
            code=expect_string(data.get("code"), "violation.code"),
            message=expect_string(data.get("message"), "violation.message"),
            field_path=data.get("field_path"),
            expected=data.get("expected"),
            observed=data.get("observed"),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field_path is not None:
            payload["field_path"] = self.field_path
        if self.expected is not None:
            payload["expected"] = self.expected
        if self.observed is not None:
            payload["observed"] = self.observed
        return payload


@dataclass(frozen=True)
class ActionIntent:
    intent_id: str
    issued_at: datetime
    expires_at: datetime
    tenant: TenantRef
    requester: PartyRef
    action: ActionSpec
    target: TargetRef
    idempotency_key: str | None = None
    justification: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    evidence_refs: tuple[EvidenceRef, ...] = ()
    metadata: dict[str, JsonScalar] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ActionIntent":
        data = expect_mapping(raw, "action_intent")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "action_intent" or contract.get("version") != "v1":
            raise ValueError("contract must declare action_intent v1")
        evidence_refs = tuple(EvidenceRef.from_dict(item) for item in data.get("evidence_refs", []))
        return cls(
            intent_id=expect_string(data.get("intent_id"), "intent_id"),
            idempotency_key=data.get("idempotency_key"),
            issued_at=parse_timestamp(data.get("issued_at"), "issued_at"),
            expires_at=parse_timestamp(data.get("expires_at"), "expires_at"),
            tenant=TenantRef.from_dict(data.get("tenant")),
            requester=PartyRef.from_dict(data.get("requester"), "requester"),
            action=ActionSpec.from_dict(data.get("action")),
            target=TargetRef.from_dict(data.get("target")),
            justification=data.get("justification"),
            context=dict(data.get("context", {})),
            evidence_refs=evidence_refs,
            metadata=dict(data.get("metadata", {})),
            extensions=dict(data.get("extensions", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": self.intent_id,
            "issued_at": format_timestamp(self.issued_at),
            "expires_at": format_timestamp(self.expires_at),
            "tenant": self.tenant.to_dict(),
            "requester": self.requester.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
        }
        if self.idempotency_key is not None:
            payload["idempotency_key"] = self.idempotency_key
        if self.justification is not None:
            payload["justification"] = self.justification
        if self.context:
            payload["context"] = self.context
        if self.evidence_refs:
            payload["evidence_refs"] = [item.to_dict() for item in self.evidence_refs]
        if self.metadata:
            payload["metadata"] = self.metadata
        if self.extensions:
            payload["extensions"] = self.extensions
        return payload


@dataclass(frozen=True)
class PCCB:
    pccb_id: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    issuer: PartyRef
    subject: PartyRef
    tenant: TenantRef
    audience: AudienceRef
    action: ActionSpec
    target: TargetRef
    scope: ScopeSpec
    nonce: str
    action_hash: ActionHashSpec
    signature: SignatureSpec
    intent_id: str | None = None
    escrow_id: str | None = None
    extensions: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PCCB":
        data = expect_mapping(raw, "pccb")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "pccb" or contract.get("version") != "v1":
            raise ValueError("contract must declare pccb v1")
        escrow_reference = data.get("escrow_reference") or {}
        return cls(
            pccb_id=expect_string(data.get("pccb_id"), "pccb_id"),
            intent_id=data.get("intent_id"),
            issued_at=parse_timestamp(data.get("issued_at"), "issued_at"),
            not_before=parse_timestamp(data.get("not_before"), "not_before"),
            expires_at=parse_timestamp(data.get("expires_at"), "expires_at"),
            issuer=PartyRef.from_dict(data.get("issuer"), "issuer"),
            subject=PartyRef.from_dict(data.get("subject"), "subject"),
            tenant=TenantRef.from_dict(data.get("tenant")),
            audience=AudienceRef.from_dict(data.get("audience")),
            action=ActionSpec.from_dict(data.get("action")),
            target=TargetRef.from_dict(data.get("target")),
            scope=ScopeSpec.from_dict(data.get("scope")),
            nonce=expect_string(data.get("nonce"), "nonce"),
            action_hash=ActionHashSpec.from_dict(data.get("action_hash")),
            signature=SignatureSpec.from_dict(data.get("signature")),
            escrow_id=escrow_reference.get("escrow_id"),
            extensions=dict(data.get("extensions", {})),
        )

    def unsigned_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "pccb", "version": "v1"},
            "pccb_id": self.pccb_id,
            "issued_at": format_timestamp(self.issued_at),
            "not_before": format_timestamp(self.not_before),
            "expires_at": format_timestamp(self.expires_at),
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "tenant": self.tenant.to_dict(),
            "audience": self.audience.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
            "scope": self.scope.to_dict(),
            "nonce": self.nonce,
            "action_hash": self.action_hash.to_dict(),
        }
        if self.intent_id is not None:
            payload["intent_id"] = self.intent_id
        if self.escrow_id is not None:
            payload["escrow_reference"] = {"escrow_id": self.escrow_id, "single_use": self.scope.single_use}
        if self.extensions:
            payload["extensions"] = self.extensions
        return payload

    def to_dict(self) -> dict[str, Any]:
        payload = self.unsigned_payload()
        payload["signature"] = self.signature.to_dict()
        return payload


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    intent_id: str
    occurred_at: datetime
    outcome: str
    tenant: TenantRef
    subject: PartyRef
    action: ActionSpec
    target: TargetRef
    summary: str
    phase: str | None = None
    correlation: CorrelationRef | None = None
    reason_codes: tuple[str, ...] = ()
    follow_up: dict[str, Any] = field(default_factory=dict)
    side_effects: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, JsonScalar] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Receipt":
        data = expect_mapping(raw, "receipt")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "receipt" or contract.get("version") != "v1":
            raise ValueError("contract must declare receipt v1")
        reason_codes_raw = data.get("reason_codes", [])
        if not isinstance(reason_codes_raw, list):
            raise ValueError("reason_codes must be an array when provided")
        return cls(
            receipt_id=expect_string(data.get("receipt_id"), "receipt_id"),
            intent_id=expect_string(data.get("intent_id"), "intent_id"),
            occurred_at=parse_timestamp(data.get("occurred_at"), "occurred_at"),
            outcome=expect_string(data.get("outcome"), "outcome"),
            phase=data.get("phase"),
            tenant=TenantRef.from_dict(data.get("tenant")),
            subject=PartyRef.from_dict(data.get("subject"), "subject"),
            action=ActionSpec.from_dict(data.get("action")),
            target=TargetRef.from_dict(data.get("target")),
            correlation=CorrelationRef.from_dict(data.get("correlation")) if data.get("correlation") else None,
            summary=expect_string(data.get("summary"), "summary"),
            reason_codes=tuple(expect_string(item, "reason_codes[]") for item in reason_codes_raw),
            follow_up=dict(data.get("follow_up", {})),
            side_effects=dict(data.get("side_effects", {})),
            details=dict(data.get("details", {})),
            metadata=dict(data.get("metadata", {})),
            extensions=dict(data.get("extensions", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "receipt", "version": "v1"},
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "occurred_at": format_timestamp(self.occurred_at),
            "outcome": self.outcome,
            "tenant": self.tenant.to_dict(),
            "subject": self.subject.to_dict(),
            "action": self.action.to_dict(),
            "target": self.target.to_dict(),
            "summary": self.summary,
        }
        if self.phase is not None:
            payload["phase"] = self.phase
        if self.correlation is not None and self.correlation.to_dict():
            payload["correlation"] = self.correlation.to_dict()
        if self.reason_codes:
            payload["reason_codes"] = list(self.reason_codes)
        if self.follow_up:
            payload["follow_up"] = self.follow_up
        if self.side_effects:
            payload["side_effects"] = self.side_effects
        if self.details:
            payload["details"] = self.details
        if self.metadata:
            payload["metadata"] = self.metadata
        if self.extensions:
            payload["extensions"] = self.extensions
        return payload


@dataclass(frozen=True, init=False)
class Refusal:
    refusal_id: str
    category: str
    reason_code: str
    message: str
    retryable: bool
    refused_at: datetime
    intent_id: str | None = None
    tenant: TenantRef | None = None
    subject: PartyRef | None = None
    audience: AudienceRef | None = None
    action: ActionSpec | None = None
    target: TargetRef | None = None
    correlation: CorrelationRef | None = None
    rule_refs: tuple[str, ...] = ()
    violations: tuple[Violation, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        refusal_id: str,
        category: str,
        reason_code: str | None = None,
        message: str | None = None,
        retryable: bool | None = None,
        refused_at: datetime | None = None,
        intent_id: str | None = None,
        tenant: TenantRef | None = None,
        subject: PartyRef | None = None,
        audience: AudienceRef | None = None,
        action: ActionSpec | None = None,
        target: TargetRef | None = None,
        correlation: CorrelationRef | None = None,
        rule_refs: tuple[str, ...] = (),
        violations: tuple[Violation, ...] = (),
        details: dict[str, Any] | None = None,
        extensions: dict[str, Any] | None = None,
        *,
        refusal_code: str | None = None,
    ) -> None:
        if refusal_code is not None:
            warnings.warn(
                "Refusal(refusal_code=...) is deprecated; use reason_code=...",
                DeprecationWarning,
                stacklevel=2,
            )
        if reason_code is not None and refusal_code is not None and reason_code != refusal_code:
            raise ValueError("reason_code and refusal_code must match when both are provided")
        resolved_reason_code = reason_code if reason_code is not None else refusal_code
        if resolved_reason_code is None:
            raise TypeError("Refusal requires reason_code")
        if message is None:
            raise TypeError("Refusal requires message")
        if retryable is None:
            raise TypeError("Refusal requires retryable")
        if refused_at is None:
            raise TypeError("Refusal requires refused_at")

        object.__setattr__(self, "refusal_id", refusal_id)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "reason_code", resolved_reason_code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "retryable", retryable)
        object.__setattr__(self, "refused_at", refused_at)
        object.__setattr__(self, "intent_id", intent_id)
        object.__setattr__(self, "tenant", tenant)
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "audience", audience)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "correlation", correlation)
        object.__setattr__(self, "rule_refs", rule_refs)
        object.__setattr__(self, "violations", violations)
        object.__setattr__(self, "details", dict(details or {}))
        object.__setattr__(self, "extensions", dict(extensions or {}))

    @property
    def refusal_code(self) -> str:
        """Deprecated compatibility alias for :attr:`reason_code`."""

        warnings.warn(
            "Refusal.refusal_code is deprecated; use reason_code",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.reason_code

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Refusal":
        data = expect_mapping(raw, "refusal")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "refusal" or contract.get("version") != "v1":
            raise ValueError("contract must declare refusal v1")
        rule_refs_raw = data.get("rule_refs", [])
        if not isinstance(rule_refs_raw, list):
            raise ValueError("rule_refs must be an array when provided")
        violations_raw = data.get("violations", [])
        if not isinstance(violations_raw, list):
            raise ValueError("violations must be an array when provided")
        reason_code_raw = data.get("reason_code")
        legacy_refusal_code_raw = data.get("refusal_code")
        if reason_code_raw is not None and legacy_refusal_code_raw is not None:
            if reason_code_raw != legacy_refusal_code_raw:
                raise ValueError("reason_code and refusal_code must match when both are provided")
        reason_code = reason_code_raw if reason_code_raw is not None else legacy_refusal_code_raw
        return cls(
            refusal_id=expect_string(data.get("refusal_id"), "refusal_id"),
            intent_id=data.get("intent_id"),
            category=expect_string(data.get("category"), "category"),
            reason_code=expect_string(reason_code, "reason_code"),
            message=expect_string(data.get("message"), "message"),
            retryable=expect_bool(data.get("retryable"), "retryable"),
            refused_at=parse_timestamp(data.get("refused_at"), "refused_at"),
            tenant=TenantRef.from_dict(data.get("tenant")) if data.get("tenant") else None,
            subject=PartyRef.from_dict(data.get("subject"), "subject") if data.get("subject") else None,
            audience=AudienceRef.from_dict(data.get("audience")) if data.get("audience") else None,
            action=ActionSpec.from_dict(data.get("action")) if data.get("action") else None,
            target=TargetRef.from_dict(data.get("target")) if data.get("target") else None,
            correlation=CorrelationRef.from_dict(data.get("correlation")) if data.get("correlation") else None,
            rule_refs=tuple(expect_string(item, "rule_refs[]") for item in rule_refs_raw),
            violations=tuple(Violation.from_dict(item) for item in violations_raw),
            details=dict(data.get("details", {})),
            extensions=dict(data.get("extensions", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "refusal", "version": "v1"},
            "refusal_id": self.refusal_id,
            "category": self.category,
            "reason_code": self.reason_code,
            "message": self.message,
            "retryable": self.retryable,
            "refused_at": format_timestamp(self.refused_at),
        }
        if self.intent_id is not None:
            payload["intent_id"] = self.intent_id
        if self.tenant is not None:
            payload["tenant"] = self.tenant.to_dict()
        if self.subject is not None:
            payload["subject"] = self.subject.to_dict()
        if self.audience is not None:
            payload["audience"] = self.audience.to_dict()
        if self.action is not None:
            payload["action"] = self.action.to_dict()
        if self.target is not None:
            payload["target"] = self.target.to_dict()
        if self.correlation is not None and self.correlation.to_dict():
            payload["correlation"] = self.correlation.to_dict()
        if self.rule_refs:
            payload["rule_refs"] = list(self.rule_refs)
        if self.violations:
            payload["violations"] = [item.to_dict() for item in self.violations]
        if self.details:
            payload["details"] = self.details
        if self.extensions:
            payload["extensions"] = self.extensions
        return payload


@dataclass(frozen=True)
class ExecutionAnchor:
    published_at: datetime
    outcome: str
    action_hash: ActionHashSpec
    pccb_digest: DigestSpec
    receipt_digest: DigestSpec | None = None
    refusal_digest: DigestSpec | None = None
    metadata: dict[str, JsonScalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.outcome not in {"executed", "refused"}:
            raise ValueError("outcome must be 'executed' or 'refused'")
        if self.outcome == "executed":
            if self.receipt_digest is None:
                raise ValueError("receipt_digest is required when outcome is 'executed'")
            if self.refusal_digest is not None:
                raise ValueError("refusal_digest must not be set when outcome is 'executed'")
        if self.outcome == "refused":
            if self.refusal_digest is None:
                raise ValueError("refusal_digest is required when outcome is 'refused'")
            if self.receipt_digest is not None:
                raise ValueError("receipt_digest must not be set when outcome is 'refused'")
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not key:
                raise ValueError("metadata keys must be non-empty strings")
            expect_json_scalar(value, f"metadata.{key}")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExecutionAnchor":
        data = expect_mapping(raw, "execution_anchor")
        contract = expect_mapping(data.get("contract"), "contract")
        if contract.get("name") != "execution_anchor" or contract.get("version") != "v1":
            raise ValueError("contract must declare execution_anchor v1")
        metadata_raw = data.get("metadata", {})
        metadata_mapping = expect_mapping(metadata_raw, "metadata") if metadata_raw else {}
        metadata = {
            expect_string(key, "metadata key"): expect_json_scalar(value, f"metadata.{key}")
            for key, value in metadata_mapping.items()
        }
        return cls(
            published_at=parse_timestamp(data.get("published_at"), "published_at"),
            outcome=expect_string(data.get("outcome"), "outcome"),
            action_hash=ActionHashSpec.from_dict(data.get("action_hash")),
            pccb_digest=DigestSpec.from_dict(data.get("pccb_digest"), "pccb_digest"),
            receipt_digest=DigestSpec.from_dict(data.get("receipt_digest"), "receipt_digest")
            if data.get("receipt_digest")
            else None,
            refusal_digest=DigestSpec.from_dict(data.get("refusal_digest"), "refusal_digest")
            if data.get("refusal_digest")
            else None,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "execution_anchor", "version": "v1"},
            "published_at": format_timestamp(self.published_at),
            "outcome": self.outcome,
            "action_hash": self.action_hash.to_dict(),
            "pccb_digest": self.pccb_digest.to_dict(),
        }
        if self.receipt_digest is not None:
            payload["receipt_digest"] = self.receipt_digest.to_dict()
        if self.refusal_digest is not None:
            payload["refusal_digest"] = self.refusal_digest.to_dict()
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


# ---------------------------------------------------------------------
# Blessed PCCB proof transport API
# ---------------------------------------------------------------------
#
# PCCB is a frozen dataclass. Do not attach runtime-only fields to a proof.
# Use these methods when a proof crosses a process, service, API, MCP or HTTP
# boundary.
#
#   wire = proof.to_wire()
#   proof = PCCB.from_wire(wire)
#

def _actenon_pccb_value_to_wire(value):
    from dataclasses import asdict, is_dataclass
    from datetime import datetime

    if isinstance(value, datetime):
        return value.isoformat()

    if is_dataclass(value):
        return {
            key: _actenon_pccb_value_to_wire(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            key: _actenon_pccb_value_to_wire(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_actenon_pccb_value_to_wire(item) for item in value]

    return value


def _actenon_pccb_value_from_wire(value):
    from datetime import datetime

    if isinstance(value, dict):
        return {
            key: _actenon_pccb_value_from_wire(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_actenon_pccb_value_from_wire(item) for item in value]

    return value


def _actenon_pccb_to_dict(self):
    return _actenon_pccb_value_to_wire(self)


@classmethod
def _actenon_pccb_from_dict(cls, payload):
    from datetime import datetime

    data = dict(payload)

    for key in ("issued_at", "expires_at"):
        if isinstance(data.get(key), str):
            data[key] = datetime.fromisoformat(data[key])

    return cls(**data)


def _actenon_pccb_to_wire(self):
    import base64
    import json

    raw = json.dumps(
        self.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return base64.urlsafe_b64encode(raw).decode("ascii")


@classmethod
def _actenon_pccb_from_wire(cls, value):
    import base64
    import json

    raw = base64.urlsafe_b64decode(value.encode("ascii")).decode("utf-8")
    payload = json.loads(raw)
    return cls.from_dict(payload)


PCCB.to_dict = _actenon_pccb_to_dict
PCCB.from_dict = _actenon_pccb_from_dict
PCCB.to_wire = _actenon_pccb_to_wire
PCCB.from_wire = _actenon_pccb_from_wire
