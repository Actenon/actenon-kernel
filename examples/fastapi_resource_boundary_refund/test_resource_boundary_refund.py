from examples.fastapi_resource_boundary_refund.app import (
    balances,
    client,
    ledger,
    mint_refund_proof,
    reset_ledger,
)


def test_valid_proof_executes_once_at_resource_boundary():
    reset_ledger()

    _action, _proof, proof_header = mint_refund_proof("ord-123", 2500)

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof_header},
    )

    assert response.status_code == 200
    assert ledger == [{"order_id": "ord-123", "amount_cents": 2500}]
    assert balances["ord-123"] == 97500


def test_tampered_amount_is_refused_before_side_effect():
    reset_ledger()

    _action, _proof, proof_header = mint_refund_proof("ord-123", 2500)

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 250000},
        headers={"X-Actenon-Proof": proof_header},
    )

    assert response.status_code == 403
    assert ledger == []
    assert balances["ord-123"] == 100000


def test_wrong_order_is_refused_before_side_effect():
    reset_ledger()

    _action, _proof, proof_header = mint_refund_proof("ord-123", 2500)

    response = client.post(
        "/refunds/ord-456",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof_header},
    )

    assert response.status_code == 403
    assert ledger == []
    assert balances["ord-456"] == 100000


def test_missing_proof_is_refused_before_side_effect():
    reset_ledger()

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
    )

    assert response.status_code == 403
    assert ledger == []
    assert balances["ord-123"] == 100000


def test_replay_is_refused_before_second_side_effect():
    reset_ledger()

    _action, _proof, proof_header = mint_refund_proof("ord-123", 2500)

    first = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof_header},
    )

    second = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
        headers={"X-Actenon-Proof": proof_header},
    )

    assert first.status_code == 200
    assert second.status_code == 403
    assert ledger == [{"order_id": "ord-123", "amount_cents": 2500}]
    assert balances["ord-123"] == 97500
