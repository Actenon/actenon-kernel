from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .contracts import JsonScalar, expect_mapping, expect_string, format_timestamp, parse_timestamp
from .runtime import PolicyOutcome


@dataclass(frozen=True)
class PolicyBundleRule:
    """Portable rule descriptor supplied by an external policy-control system.

    The open kernel does not interpret this as executable control-plane logic on
    its own. Instead, it provides a typed structure that other layers can use to
    move policy decisions, constraints, and workflow requirements into verifier
    or admission environments without coupling them to a single hosted product.
    """

    rule_id: str
    effect: PolicyOutcome
    summary: str
    reason_code: str
    capabilities: tuple[str, ...]
    audiences: tuple[str, ...] = ()
    parameter_constraints: dict[str, Any] = field(default_factory=dict)
    resource_selectors: tuple[dict[str, Any], ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    approver_types: tuple[str, ...] = ()
    metadata: dict[str, JsonScalar] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyBundleRule":
        data = expect_mapping(raw, "policy_bundle.rules[]")
        return cls(
            rule_id=expect_string(data.get("rule_id"), "policy_bundle.rules[].rule_id"),
            effect=expect_string(data.get("effect"), "policy_bundle.rules[].effect"),
            summary=expect_string(data.get("summary"), "policy_bundle.rules[].summary"),
            reason_code=expect_string(data.get("reason_code"), "policy_bundle.rules[].reason_code"),
            capabilities=tuple(str(item) for item in data.get("capabilities", [])),
            audiences=tuple(str(item) for item in data.get("audiences", [])),
            parameter_constraints=dict(data.get("parameter_constraints", {})),
            resource_selectors=tuple(dict(item) for item in data.get("resource_selectors", [])),
            required_evidence_types=tuple(str(item) for item in data.get("required_evidence_types", [])),
            approver_types=tuple(str(item) for item in data.get("approver_types", [])),
            metadata=dict(data.get("metadata", {})),
        )

    def applies_to(self, *, capability: str, audience: str | None = None) -> bool:
        """Return `True` when the rule applies to the supplied capability and audience."""

        if self.capabilities and capability not in self.capabilities:
            return False
        if audience is not None and self.audiences and audience not in self.audiences:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "effect": self.effect,
            "summary": self.summary,
            "reason_code": self.reason_code,
            "capabilities": list(self.capabilities),
        }
        if self.audiences:
            payload["audiences"] = list(self.audiences)
        if self.parameter_constraints:
            payload["parameter_constraints"] = self.parameter_constraints
        if self.resource_selectors:
            payload["resource_selectors"] = list(self.resource_selectors)
        if self.required_evidence_types:
            payload["required_evidence_types"] = list(self.required_evidence_types)
        if self.approver_types:
            payload["approver_types"] = list(self.approver_types)
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


@dataclass(frozen=True)
class PolicyBundle:
    """Portable policy bundle envelope suitable for external policy-plane input.

    A policy bundle is a typed snapshot of rule metadata, constraints, and
    workflow hints produced outside the kernel. The bundle is intentionally
    neutral about where those rules were authored or how a hosted control plane
    stores them.
    """

    bundle_id: str
    issued_at: datetime
    issuer: str
    rules: tuple[PolicyBundleRule, ...]
    tenant_id: str | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    audiences: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    metadata: dict[str, JsonScalar] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyBundle":
        data = expect_mapping(raw, "policy_bundle")
        contract = expect_mapping(data.get("contract"), "policy_bundle.contract")
        if contract.get("name") != "policy_bundle" or contract.get("version") != "v1":
            raise ValueError("policy bundle contract must declare policy_bundle v1")
        return cls(
            bundle_id=expect_string(data.get("bundle_id"), "policy_bundle.bundle_id"),
            issued_at=parse_timestamp(data.get("issued_at"), "policy_bundle.issued_at"),
            issuer=expect_string(data.get("issuer"), "policy_bundle.issuer"),
            rules=tuple(PolicyBundleRule.from_dict(item) for item in data.get("rules", [])),
            tenant_id=data.get("tenant_id"),
            not_before=parse_timestamp(data.get("not_before"), "policy_bundle.not_before") if data.get("not_before") else None,
            expires_at=parse_timestamp(data.get("expires_at"), "policy_bundle.expires_at") if data.get("expires_at") else None,
            audiences=tuple(str(item) for item in data.get("audiences", [])),
            capabilities=tuple(str(item) for item in data.get("capabilities", [])),
            metadata=dict(data.get("metadata", {})),
        )

    def rules_for(self, *, capability: str, audience: str | None = None) -> tuple[PolicyBundleRule, ...]:
        """Return bundle rules that apply to the supplied capability and audience."""

        return tuple(rule for rule in self.rules if rule.applies_to(capability=capability, audience=audience))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "contract": {"name": "policy_bundle", "version": "v1"},
            "bundle_id": self.bundle_id,
            "issued_at": format_timestamp(self.issued_at),
            "issuer": self.issuer,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.tenant_id is not None:
            payload["tenant_id"] = self.tenant_id
        if self.not_before is not None:
            payload["not_before"] = format_timestamp(self.not_before)
        if self.expires_at is not None:
            payload["expires_at"] = format_timestamp(self.expires_at)
        if self.audiences:
            payload["audiences"] = list(self.audiences)
        if self.capabilities:
            payload["capabilities"] = list(self.capabilities)
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload
