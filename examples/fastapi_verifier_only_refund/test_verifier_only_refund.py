from examples.fastapi_verifier_only_refund.app import (
    balances,
    client,
    ledger,
    reset_ledger,
)
from examples.fastapi_verifier_only_refund.issuer import mint_refund_proof


def test_verifier_only_endpoint_executes_valid_issuer_proof():
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


def test_verifier_only_endpoint_refuses_tampered_request():
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


def test_verifier_only_endpoint_refuses_missing_proof():
    reset_ledger()

    response = client.post(
        "/refunds/ord-123",
        json={"amount_cents": 2500},
    )

    assert response.status_code == 403
    assert ledger == []
    assert balances["ord-123"] == 100000
