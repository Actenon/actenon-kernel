from __future__ import annotations

from financial_agent import FinancialAgent


def _new_agent(tmp_path, monkeypatch) -> FinancialAgent:
    # Keep replay state isolated so every test proves only its own boundary.
    monkeypatch.setenv("ACTENON_REPLAY_DB", str(tmp_path / "actenon-replay.sqlite3"))
    return FinancialAgent()


def _assert_initial_ledger(agent: FinancialAgent) -> None:
    assert agent.ledger.balances["customer_a"] == 10_000
    assert agent.ledger.balances["external_wallet"] == 0
    assert agent.ledger.balances["safe_savings_wallet"] == 0
    assert agent.ledger.balances["attacker_wallet"] == 0
    assert agent.ledger.transfers == []


def test_missing_proof_does_not_move_money(tmp_path, monkeypatch):
    agent = _new_agent(tmp_path, monkeypatch)

    response = agent.attempt_transfer(
        amount=5_000,
        destination="external_wallet",
        proof=None,
    )

    assert response["status"] == "refused"
    assert response["reason_code"] == "PCCB_REQUIRED"
    assert response["refusal"] is not None
    assert response["receipt"] is not None
    _assert_initial_ledger(agent)


def test_wrong_amount_proof_does_not_move_money(tmp_path, monkeypatch):
    agent = _new_agent(tmp_path, monkeypatch)

    proof_for_lower_amount = agent.mint_transfer_proof(
        amount=500,
        destination="external_wallet",
    )

    response = agent.attempt_transfer(
        amount=5_000,
        destination="external_wallet",
        proof=proof_for_lower_amount,
    )

    assert response["status"] == "refused"
    assert response["reason_code"] == "INTENT_MISMATCH"
    assert response["refusal"] is not None
    _assert_initial_ledger(agent)


def test_wrong_destination_proof_does_not_move_money(tmp_path, monkeypatch):
    agent = _new_agent(tmp_path, monkeypatch)

    proof_for_safe_destination = agent.mint_transfer_proof(
        amount=5_000,
        destination="safe_savings_wallet",
    )

    response = agent.attempt_transfer(
        amount=5_000,
        destination="attacker_wallet",
        proof=proof_for_safe_destination,
    )

    assert response["status"] == "refused"
    assert response["reason_code"] == "INTENT_MISMATCH"
    assert response["refusal"] is not None
    _assert_initial_ledger(agent)


def test_replayed_proof_does_not_move_money_twice(tmp_path, monkeypatch):
    agent = _new_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=5_000,
        destination="external_wallet",
    )

    first = agent.attempt_transfer(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )
    replay = agent.attempt_transfer(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    assert first["status"] == "executed"
    assert first["receipt"] is not None

    assert replay["status"] == "refused"
    assert replay["reason_code"] == "DUPLICATE_REPLAY"
    assert replay["refusal"] is not None

    assert agent.ledger.balances["customer_a"] == 5_000
    assert agent.ledger.balances["external_wallet"] == 5_000
    assert len(agent.ledger.transfers) == 1


def test_valid_exact_proof_moves_money_once(tmp_path, monkeypatch):
    agent = _new_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=5_000,
        destination="external_wallet",
    )

    response = agent.attempt_transfer(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    assert response["status"] == "executed"
    assert response["receipt"] is not None
    assert response["payload"]["amount"] == 5_000
    assert response["payload"]["destination"] == "external_wallet"

    assert agent.ledger.balances["customer_a"] == 5_000
    assert agent.ledger.balances["external_wallet"] == 5_000
    assert len(agent.ledger.transfers) == 1

    # Evidence exists for the executed decision.
    assert len(agent.outcomes.receipts) == 1
    assert len(agent.outcomes.refusals) == 0
