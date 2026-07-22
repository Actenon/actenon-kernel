from __future__ import annotations

import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from actenon import ActenonGate
from actenon.adapters.fastapi import ACTENON_PROOF_HEADER, encode_json_header
from actenon.gate import GateOutcome
from actenon.models import ActionIntent, ActionSpec, PartyRef, TargetRef, TenantRef
from actenon.replay import ReplayProtector, SqliteReplayStore


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class PayoutRequest(BaseModel):
    amount_minor: int
    destination: str


def _intent(payload: dict[str, object]) -> ActionIntent:
    destination = str(payload["destination"])
    return ActionIntent(
        intent_id=f"intent_fastapi_{payload['amount_minor']}_{destination}",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        tenant=TenantRef(tenant_id="tenant_adapters"),
        requester=PartyRef(type="agent", id="fastapi-agent"),
        action=ActionSpec(
            name="payout.release",
            capability="payment.release",
            parameters={
                "amount_minor": int(payload["amount_minor"]),
                "destination": destination,
            },
        ),
        target=TargetRef(
            resource_type="payout_destination",
            resource_id=destination,
        ),
    )


def test_fastapi_dependency_refuses_before_handler_and_executes_valid_payout() -> None:
    side_effects: list[dict[str, object]] = []
    handler_calls: list[str] = []
    with TemporaryDirectory() as tempdir, warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        gate = ActenonGate.local_dev(
            audience="service:payout-api",
            replay_protector=ReplayProtector(
                SqliteReplayStore(Path(tempdir) / "replay.sqlite3")
            ),
            clock=lambda: NOW,
        )
        protected_dependency = gate.fastapi_dependency(
            audience="service:payout-api",
            action_builder=_intent,
            side_effect=lambda payload: side_effects.append(dict(payload))
            or {"payout_id": "payout_local_001"},
            body_model=PayoutRequest,
        )
        app = FastAPI()

        @app.post("/payouts")
        def create_payout(
            body: PayoutRequest,
            outcome: GateOutcome = Depends(protected_dependency),
        ) -> dict[str, object]:
            handler_calls.append(body.destination)
            return outcome.to_dict()

        client = TestClient(app)
        approved = {"amount_minor": 1250, "destination": "bank:approved"}
        diverted = {"amount_minor": 1250, "destination": "bank:diverted"}
        approved_proof = gate.mint_proof(_intent(approved))
        diverted_proof = gate.mint_proof(_intent(approved))

        invalid = client.post(
            "/payouts",
            json={"amount_minor": "not-an-integer", "destination": "bank:approved"},
            headers={ACTENON_PROOF_HEADER: encode_json_header(approved_proof)},
        )
        missing = client.post("/payouts", json=approved)
        valid = client.post(
            "/payouts",
            json=approved,
            headers={ACTENON_PROOF_HEADER: encode_json_header(approved_proof)},
        )
        mismatch = client.post(
            "/payouts",
            json=diverted,
            headers={ACTENON_PROOF_HEADER: encode_json_header(diverted_proof)},
        )

    assert invalid.status_code == 422
    assert missing.status_code == 403
    assert missing.json()["detail"]["reason_code"] == "PCCB_REQUIRED"
    assert missing.json()["detail"]["unmet_requirements"] == []
    assert valid.status_code == 200
    assert valid.json()["outcome"] == "executed"
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"]["reason_code"] in ("INTENT_MISMATCH", "TARGET_MISMATCH", "ACTION_MISMATCH")
    assert side_effects == [approved]
    assert handler_calls == ["bank:approved"]
