from fastapi.testclient import TestClient

from examples.fastapi_resource_boundary_refund.app import (
    app,
    build_refund_action,
    gate,
    reset_ledger,
)


client = TestClient(app)


def test_valid_proof_executes_once_at_resource_boundary():
    reset_ledger()

    action = build_refund_action(order_id="ord-123", amount_cents=2500)
    proof = gate.mint_proof(action)

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "EXECUTED"

    ledger = client.get("/ledger").json()["events"]
    assert ledger == [{"order_id": "ord-123", "amount_cents": 2500}]


def test_tampered_amount_is_refused_before_side_effect():
    reset_ledger()

    action = build_refund_action(order_id="ord-123", amount_cents=2500)
    proof = gate.mint_proof(action)

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 250000},
        headers={"X-Actenon-Proof": proof},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["status"] == "REFUSED"

    ledger = client.get("/ledger").json()["events"]
    assert ledger == []


def test_wrong_order_is_refused_before_side_effect():
    reset_ledger()

    action = build_refund_action(order_id="ord-123", amount_cents=2500)
    proof = gate.mint_proof(action)

    response = client.post(
        "/refunds/ord-456",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["status"] == "REFUSED"

    ledger = client.get("/ledger").json()["events"]
    assert ledger == []


def test_missing_proof_is_refused_before_side_effect():
    reset_ledger()

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["status"] == "REFUSED"

    ledger = client.get("/ledger").json()["events"]
    assert ledger == []


def test_replay_is_refused_before_second_side_effect():
    reset_ledger()

    action = build_refund_action(order_id="ord-123", amount_cents=2500)
    proof = gate.mint_proof(action)

    first = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof},
    )

    second = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof},
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["detail"]["status"] == "REFUSED"

    ledger = client.get("/ledger").json()["events"]
    assert ledger == [{"order_id": "ord-123", "amount_cents": 2500}]
