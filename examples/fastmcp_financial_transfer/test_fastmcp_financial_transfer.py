from __future__ import annotations

from examples.fastmcp_financial_transfer import mcp_server


def _reset_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("ACTENON_REPLAY_DB", str(tmp_path / "actenon-replay.sqlite3"))
    mcp_server.secure_agent = mcp_server.FinancialAgent()
    return mcp_server.secure_agent


def test_fastmcp_missing_proof_refuses_before_money_moves(tmp_path, monkeypatch):
    agent = _reset_agent(tmp_path, monkeypatch)

    result = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="external_wallet",
        proof=None,
    )

    assert result["status"] == "refused"
    assert result["reason_code"] == "PCCB_REQUIRED"
    assert agent.ledger.balances["customer_a"] == 10_000
    assert agent.ledger.balances["external_wallet"] == 0
    assert agent.ledger.transfers == []


def test_fastmcp_wrong_amount_proof_refuses_before_money_moves(tmp_path, monkeypatch):
    agent = _reset_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=500,
        destination="external_wallet",
    )

    result = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    assert result["status"] == "refused"
    assert result["reason_code"] == "INTENT_MISMATCH"
    assert agent.ledger.balances["customer_a"] == 10_000
    assert agent.ledger.balances["external_wallet"] == 0
    assert agent.ledger.transfers == []


def test_fastmcp_wrong_destination_proof_refuses_before_money_moves(tmp_path, monkeypatch):
    agent = _reset_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=5_000,
        destination="safe_savings_wallet",
    )

    result = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="attacker_wallet",
        proof=proof,
    )

    assert result["status"] == "refused"
    assert result["reason_code"] == "INTENT_MISMATCH"
    assert agent.ledger.balances["customer_a"] == 10_000
    assert agent.ledger.balances["attacker_wallet"] == 0
    assert agent.ledger.transfers == []


def test_fastmcp_replay_refuses_second_transfer(tmp_path, monkeypatch):
    agent = _reset_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=5_000,
        destination="external_wallet",
    )

    first = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    replay = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    assert first["status"] == "executed"
    assert replay["status"] == "refused"
    assert replay["reason_code"] == "DUPLICATE_REPLAY"

    assert agent.ledger.balances["customer_a"] == 5_000
    assert agent.ledger.balances["external_wallet"] == 5_000
    assert len(agent.ledger.transfers) == 1


def test_fastmcp_valid_exact_proof_executes_once_with_receipt(tmp_path, monkeypatch):
    agent = _reset_agent(tmp_path, monkeypatch)

    proof = agent.mint_transfer_proof(
        amount=5_000,
        destination="external_wallet",
    )

    result = mcp_server.transfer_funds_impl(
        amount=5_000,
        destination="external_wallet",
        proof=proof,
    )

    assert result["status"] == "executed"
    assert result["receipt"] is not None
    assert result["payload"]["amount"] == 5_000
    assert result["payload"]["destination"] == "external_wallet"

    assert agent.ledger.balances["customer_a"] == 5_000
    assert agent.ledger.balances["external_wallet"] == 5_000
    assert len(agent.ledger.transfers) == 1
