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


# ---------------------------------------------------------------------------
# PCCB wire transport helpers
# ---------------------------------------------------------------------------
#
# These helpers are intentionally attached after the dataclass definition so
# they work without changing the existing PCCB constructor/signature.
#
# Use:
#   proof_header = proof.to_wire()
#   proof = PCCB.from_wire(proof_header)
#
# The wire form is URL-safe base64 JSON. It is suitable for HTTP headers,
# queues, webhooks and test clients.

import base64 as _actenon_base64
import dataclasses as _actenon_dataclasses
import json as _actenon_json
from datetime import datetime as _actenon_datetime


def _actenon_wire_jsonable(value):
    if isinstance(value, _actenon_datetime):
        return value.isoformat()
    if _actenon_dataclasses.is_dataclass(value):
        return {
            key: _actenon_wire_jsonable(val)
            for key, val in _actenon_dataclasses.asdict(value).items()
        }
    if isinstance(value, dict):
        return {key: _actenon_wire_jsonable(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_actenon_wire_jsonable(item) for item in value]
    return value


def _pccb_to_dict(self):
    return _actenon_wire_jsonable(self)


def _pccb_from_dict(cls, payload):
    data = dict(payload)

    for key in ("issued_at", "expires_at"):
        value = data.get(key)
        if isinstance(value, str):
            data[key] = _actenon_datetime.fromisoformat(value)

    return cls(**data)


def _pccb_to_wire(self):
    raw = _actenon_json.dumps(
        self.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _actenon_base64.urlsafe_b64encode(raw).decode("ascii")


def _pccb_from_wire(cls, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("PCCB wire value must be a non-empty string")

    try:
        raw = _actenon_base64.urlsafe_b64decode(value.encode("ascii"))
        payload = _actenon_json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid PCCB wire value") from exc

    return cls.from_dict(payload)


PCCB.to_dict = _pccb_to_dict
PCCB.from_dict = classmethod(_pccb_from_dict)
PCCB.to_wire = _pccb_to_wire
PCCB.from_wire = classmethod(_pccb_from_wire)

