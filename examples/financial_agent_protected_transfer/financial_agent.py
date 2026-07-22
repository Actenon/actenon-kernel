from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from actenon import ActenonGate, PCCB
from actenon.receipts import InMemoryOutcomeWriter


@dataclass
class InMemoryLedger:
    """Tiny in-memory ledger used only for the local example tests."""

    balances: dict[str, int] = field(
        default_factory=lambda: {
            "customer_a": 10_000,
            "external_wallet": 0,
            "safe_savings_wallet": 0,
            "attacker_wallet": 0,
        }
    )
    transfers: list[dict[str, Any]] = field(default_factory=list)

    def transfer(self, *, source: str, destination: str, amount: int) -> dict[str, Any]:
        if amount <= 0:
            raise ValueError("amount must be positive")
        if self.balances[source] < amount:
            raise ValueError("insufficient funds")

        self.balances[source] -= amount
        self.balances[destination] = self.balances.get(destination, 0) + amount

        transfer_id = f"tx_{len(self.transfers) + 1:04d}"
        record = {
            "transfer_id": transfer_id,
            "source": source,
            "destination": destination,
            "amount": amount,
        }
        self.transfers.append(record)
        return record


class FinancialAgent:
    """A minimal financial agent protected by Actenon at the execution boundary.

    The agent is allowed to decide that it wants to transfer money.

    The ledger mutation only happens inside the Actenon-protected boundary.
    Missing, mismatched, expired, replayed, or policy-denied proof must refuse
    before the ledger mutates.
    """

    def __init__(self, *, clock: Any | None = None) -> None:
        self.now = clock or (lambda: datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
        self.ledger = InMemoryLedger()
        self.outcomes = InMemoryOutcomeWriter()

        # Local development mode only. Production deployments should pass a verifier
        # rooted in asymmetric/KMS/HSM signing custody rather than the local demo signer.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            self.gate = ActenonGate.local_dev(
                audience="service:financial-ledger-transfer",
                issuer="service:financial-approval-service",
                clock=self.now,
                outcome_writer=self.outcomes,
            )

    def build_transfer_action(
        self,
        *,
        amount: int,
        destination: str,
        source: str = "customer_a",
        tenant_id: str = "tenant_finance_demo",
        requester_id: str = "financial-agent",
    ) -> dict[str, Any]:
        """Build the exact Action Intent for the transfer being attempted."""

        issued_at = self.now()
        expires_at = issued_at + timedelta(minutes=5)

        return {
            "contract": {"name": "action_intent", "version": "v1"},
            "intent_id": (
                f"intent_transfer_{tenant_id}_{requester_id}_{source}_"
                f"{destination}_{amount}"
            ),
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "tenant": {"tenant_id": tenant_id},
            "requester": {"type": "agent", "id": requester_id},
            "action": {
                "name": "financial.transfer_funds",
                "capability": "financial.transfer",
                "parameters": {
                    "source": source,
                    "destination": destination,
                    "amount": amount,
                    "currency": "GBP",
                },
            },
            "target": {
                "resource_type": "ledger_account",
                "resource_id": source,
                "selectors": {
                    "source": source,
                    "destination": destination,
                    "currency": "GBP",
                },
            },
        }

    def mint_transfer_proof(
        self,
        *,
        amount: int,
        destination: str,
        source: str = "customer_a",
        tenant_id: str = "tenant_finance_demo",
        requester_id: str = "financial-agent",
    ) -> PCCB:
        """Mint local development proof for one exact transfer intent."""

        action = self.build_transfer_action(
            amount=amount,
            destination=destination,
            source=source,
            tenant_id=tenant_id,
            requester_id=requester_id,
        )
        return self.gate.mint_proof(action)

    def attempt_transfer(
        self,
        *,
        amount: int,
        destination: str,
        proof: PCCB | dict[str, Any] | None,
        source: str = "customer_a",
        tenant_id: str = "tenant_finance_demo",
        requester_id: str = "financial-agent",
    ) -> dict[str, Any]:
        """Attempt a transfer through the Actenon-protected boundary."""

        action = self.build_transfer_action(
            amount=amount,
            destination=destination,
            source=source,
            tenant_id=tenant_id,
            requester_id=requester_id,
        )

        outcome = self.gate.protect(
            action,
            proof,
            lambda: self.ledger.transfer(
                source=source,
                destination=destination,
                amount=amount,
            ),
        )

        if outcome.ok:
            return {
                "status": "executed",
                "payload": outcome.payload,
                "receipt": outcome.receipt,
                "refusal": None,
                "reason_code": None,
            }

        return {
            "status": "refused",
            "payload": None,
            "receipt": outcome.receipt,
            "refusal": outcome.refusal,
            "reason_code": outcome.reason_code,
        }
