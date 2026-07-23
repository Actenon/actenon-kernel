import importlib.util
from pathlib import Path


def load_demo_module():
    path = Path("examples/adversarial_rsa_policy_stress_test.py")
    spec = importlib.util.spec_from_file_location("adversarial_rsa_policy_stress_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_adversarial_rsa_policy_stress_test_blocks_all_attacks():
    module = load_demo_module()

    stats = module.run_adversarial_stress_test(runs=900, seed=1337)

    assert stats["valid_executed"] > 0
    assert stats["blocked_replay"] > 0
    assert stats["blocked_tampered_payload"] > 0
    assert stats["blocked_expired_ttl"] > 0
    assert stats["blocked_future_timestamp"] > 0
    assert stats["blocked_minter_guardrail"] > 0
    assert stats["valid_failed_erroneously"] == 0
    assert stats["undetected_attacks"] == 0
