from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Protocol
from uuid import uuid4

from actenon.models.contracts import ActionIntent, PCCB, format_timestamp
from actenon.models.runtime import DynamicContextInput


@dataclass(frozen=True)
class BrokeredCredential:
    """Public-safe reference to a credential brokered for one execution attempt.

    The broker exposes only a stable reference to credential material. Raw
    provider secrets must remain in the broker, vault, or endpoint runtime and
    must not be written into receipts, logs, or artifacts.
    """

    credential_id: str
    issued_at: datetime
    expires_at: datetime
    scope: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)
    secret_reference: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "credential_id": self.credential_id,
            "issued_at": format_timestamp(self.issued_at),
            "expires_at": format_timestamp(self.expires_at),
            "scope": list(self.scope),
            "metadata": self.metadata,
        }
        if self.secret_reference is not None:
            payload["secret_reference"] = self.secret_reference
        return payload


class CredentialBroker(Protocol):
    """Broker short-lived execution authority after proof verification."""

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        ...

    def release(self, credential: BrokeredCredential, result: Any) -> None:
        ...


class InMemoryCredentialBroker:
    """Local demo/test broker that never exposes real secret material."""

    def __init__(
        self,
        *,
        ttl: timedelta = timedelta(minutes=2),
        credential_id_factory: Callable[[], str] | None = None,
        secret_reference_prefix: str = "memory://brokered-credential",
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        self.ttl = ttl
        self.credential_id_factory = credential_id_factory or (lambda: f"cred_{uuid4().hex}")
        self.secret_reference_prefix = secret_reference_prefix.rstrip("/")
        self.issued_credentials: list[BrokeredCredential] = []
        self.released_credentials: list[tuple[BrokeredCredential, Any]] = []

    def acquire(self, intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> BrokeredCredential:
        credential_id = self.credential_id_factory()
        issued_at = context.now
        expires_at = min(issued_at + self.ttl, pccb.expires_at)
        credential = BrokeredCredential(
            credential_id=credential_id,
            issued_at=issued_at,
            expires_at=expires_at,
            scope=tuple(pccb.scope.capabilities),
            secret_reference=f"{self.secret_reference_prefix}/{credential_id}",
            metadata={
                "broker": "in_memory",
                "intent_id": intent.intent_id,
                "pccb_id": pccb.pccb_id,
                "audience": pccb.audience.to_dict(),
                "capability": intent.action.capability,
            },
        )
        self.issued_credentials.append(credential)
        return credential

    def release(self, credential: BrokeredCredential, result: Any) -> None:
        self.released_credentials.append((credential, result))
