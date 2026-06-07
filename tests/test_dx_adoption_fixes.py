from actenon import ActenonGate


def test_build_action_executes_and_refuses_tamper():
    gate = ActenonGate.local_dev(audience="service:test-dx")
    side_effects = []

    action = gate.build_action(
        "refund.issue",
        "payment.refund",
        {"order_id": "ord-123", "amount_cents": 2500},
        target_type="order",
        target_id="ord-123",
        tenant_id="demo",
        requester_id="support-agent",
    )
    proof = gate.mint_proof(action)

    ok = gate.protect(
        action,
        proof,
        lambda: side_effects.append({"order_id": "ord-123", "amount_cents": 2500}) or {"ok": True},
        audience="service:test-dx",
    )

    tampered = gate.protect(
        gate.build_action(
            "refund.issue",
            "payment.refund",
            {"order_id": "ord-123", "amount_cents": 250000},
            target_type="order",
            target_id="ord-123",
            tenant_id="demo",
            requester_id="support-agent",
        ),
        proof,
        lambda: side_effects.append({"order_id": "ord-123", "amount_cents": 250000}) or {"ok": True},
        audience="service:test-dx",
    )

    ok_d = ok if isinstance(ok, dict) else ok.to_dict()
    tampered_d = tampered if isinstance(tampered, dict) else tampered.to_dict()

    assert ok_d["outcome"] == "executed"
    assert tampered_d["outcome"] == "refused"
    assert tampered_d["reason_code"] == "INTENT_MISMATCH"
    assert side_effects == [{"order_id": "ord-123", "amount_cents": 2500}]


def test_constructor_rejects_none_verifier():
    try:
        ActenonGate(verifier=None, issuer="issuer:test", audience="service:test")
    except ValueError as exc:
        assert "requires a verifier" in str(exc)
        assert "local_dev" in str(exc)
    else:
        raise AssertionError("ActenonGate accepted verifier=None")
