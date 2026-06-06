from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from actenon import ActenonGate
from actenon.core import EscrowConfigurationError, EscrowValidationError
from actenon.escrow import InMemoryCapabilityEscrow
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.receipts import InMemoryOutcomeWriter
from actenon.replay import ReplayProtector, SqliteReplayStore


def _intent(now: datetime) -> ActionIntent:
    return ActionIntent(
        intent_id="intent_escrow_enable_001",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        tenant=TenantRef(tenant_id="tenant_escrow_enable"),
        requester=PartyRef(type="agent", id="escrow-enable-agent"),
        action=ActionSpec(
            name="payment.release",
            capability="payment.release",
            parameters={"payment_id": "payment_synthetic_001", "amount_minor": 1250},
        ),
        target=TargetRef(
            resource_type="payment",
            resource_id="payment_synthetic_001",
        ),
    )


def _gate(
    *,
    now: datetime,
    replay_path: Path,
    escrow: InMemoryCapabilityEscrow | None,
    outcome_writer: InMemoryOutcomeWriter | None = None,
) -> ActenonGate:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return ActenonGate.local_dev(
            audience="service:payments-protected-endpoint",
            escrow=escrow,
            outcome_writer=outcome_writer,
            replay_protector=ReplayProtector(SqliteReplayStore(replay_path)),
            clock=lambda: now,
        )


def test_escrow_enabled_gate_executes_once_then_refuses_replay() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    intent = _intent(now)
    effects: list[str] = []

    with TemporaryDirectory() as tempdir:
        escrow = InMemoryCapabilityEscrow()
        gate = _gate(
            now=now,
            replay_path=Path(tempdir) / "replay.sqlite3",
            escrow=escrow,
        )
        proof = gate.mint_proof(intent)

        first = gate.protect(intent, proof, lambda: effects.append("released"))
        second = gate.protect(intent, proof, lambda: effects.append("released-again"))

    assert proof.escrow_id is not None
    assert first.ok
    assert first.reason_code is None
    assert second.reason_code == "DUPLICATE_REPLAY"
    assert second.reason_code != "ESCROW_REFERENCE_MISSING"
    assert effects == ["released"]


def test_legacy_proof_without_escrow_reference_raises_setup_error() -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    intent = _intent(now)

    with TemporaryDirectory() as tempdir:
        root = Path(tempdir)
        legacy_gate = _gate(
            now=now,
            replay_path=root / "legacy-replay.sqlite3",
            escrow=None,
        )
        legacy_proof = legacy_gate.mint_proof(intent)
        writer = InMemoryOutcomeWriter()
        escrow_gate = _gate(
            now=now,
            replay_path=root / "escrow-replay.sqlite3",
            escrow=InMemoryCapabilityEscrow(),
            outcome_writer=writer,
        )

        with pytest.raises(EscrowConfigurationError) as raised:
            escrow_gate.protect(
                intent,
                legacy_proof,
                lambda: pytest.fail("legacy proof reached the side effect"),
            )

    assert isinstance(raised.value, EscrowValidationError)
    assert raised.value.refusal_code == "ESCROW_CONFIGURATION_INVALID"
    assert raised.value.details["missing_field"] == "pccb.escrow_reference.escrow_id"
    assert raised.value.details["minting_step"] == "ActenonGate.mint_proof(...)"
    assert "ActenonGate.mint_proof(...)" in str(raised.value)
    assert writer.receipts == []
    assert writer.refusals == []
