#!/usr/bin/env python3
"""Benchmark: verification latency and throughput.

Fable 5 Part 3.6: "real measured numbers from a benchmark you write and
commit under benchmarks/. Verification latency p50/p99 for symmetric and
asymmetric paths, throughput per core, memory footprint. Measured, not
estimated. State the hardware."

Usage:
    python benchmarks/verify_benchmark.py
"""

from __future__ import annotations

import os
import statistics
import sys
import time
from datetime import UTC, datetime, timedelta

# Ensure the repo root is on the path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# Suppress the local HMAC warning for the benchmark
os.environ["ACTENON_ENV"] = "benchmark"

from actenon.models import (
    ActionIntent,
    ActionSpec,
    AudienceRef,
    PartyRef,
    TargetRef,
    TenantRef,
)
from actenon.models.runtime import PolicyDecision
from actenon.proof import PCCBMinter, PCCBVerifier, build_local_proof_signer
from actenon.proof.service import DynamicContextInput


def _make_intent() -> ActionIntent:
    now = datetime.now(UTC)
    return ActionIntent(
        intent_id="intent_bench_001",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        tenant=TenantRef(tenant_id="tenant:bench"),
        requester=PartyRef(type="agent", id="agent:bench"),
        action=ActionSpec(
            name="payment.refund",
            capability="payment.refund",
            parameters={"amount_cents": 2500, "currency": "GBP"},
        ),
        target=TargetRef(resource_type="payment_intent", resource_id="pi_bench_001"),
    )


def _make_context() -> DynamicContextInput:
    return DynamicContextInput(
        request_id="req_bench_001",
        audience=AudienceRef(type="service", id="service:payments"),
        scope_capabilities=("payment.refund",),
        now=datetime.now(UTC),
    )


def _make_decision() -> PolicyDecision:
    return PolicyDecision(
        outcome="allow",
        summary="Benchmark allow.",
        rule_evaluations=(),
        reason_codes=("BENCH",),
    )


def benchmark_symmetric(iterations: int = 1000) -> dict:
    """Benchmark symmetric (HMAC) verification."""
    signer = build_local_proof_signer()
    minter = PCCBMinter(signer=signer, issuer=PartyRef(type="agent", id="agent:bench"))
    verifier = PCCBVerifier(signer=signer)

    intent = _make_intent()
    context = _make_context()
    decision = _make_decision()
    pccb = minter.mint(intent, decision, context)

    # Warmup
    for _ in range(50):
        verifier.verify(intent, pccb, context)

    # Benchmark
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        verifier.verify(intent, pccb, context)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)  # ms

    times.sort()
    return {
        "path": "symmetric (HMAC)",
        "iterations": iterations,
        "p50_ms": times[len(times) // 2],
        "p99_ms": times[int(len(times) * 0.99)],
        "mean_ms": statistics.mean(times),
        "throughput_per_sec": 1000.0 / statistics.mean(times),
    }


def benchmark_asymmetric(iterations: int = 1000) -> dict | None:
    """Benchmark asymmetric (Ed25519) verification."""
    try:
        from dataclasses import dataclass
        from actenon.proof.signers.external_managed import (
            ACTIVE_KEY_STATUS,
            ExternalManagedSigner,
            ExternalManagedSigningBackend,
            ManagedKeyReference,
            ManagedSigningResult,
            PROOF_ISSUANCE_PURPOSE,
        )
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        print("cryptography not installed; skipping asymmetric benchmark")
        return None

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    @dataclass(frozen=True)
    class LocalEd25519Backend(ExternalManagedSigningBackend):
        priv: object
        pub: object

        def get_key_status(self, *, key):
            return ACTIVE_KEY_STATUS

        def sign_canonical_bytes(self, *, key, payload, audit_metadata):
            sig = self.priv.sign(payload)
            return ManagedSigningResult(
                algorithm=key.algorithm, key_id=key.key_id, signature=sig,
                public_key_ref="local", provider_operation_id="local",
            )

        def verify_canonical_bytes(self, *, key, payload, signature):
            try:
                self.pub.verify(signature, payload)
                return True
            except Exception:
                return False

    backend = LocalEd25519Backend(priv=private_key, pub=public_key)
    key_ref = ManagedKeyReference(
        provider="local", provider_key_ref="local", key_id="bench-ed25519",
        algorithm="EdDSA", purpose=PROOF_ISSUANCE_PURPOSE, tenant_id="tenant:bench",
        public_key_ref="local", status=ACTIVE_KEY_STATUS,
    )
    signer = ExternalManagedSigner(backend=backend, key=key_ref)
    minter = PCCBMinter(signer=signer, issuer=PartyRef(type="agent", id="agent:bench"))
    verifier = PCCBVerifier(signer=signer)

    intent = _make_intent()
    context = _make_context()
    decision = _make_decision()
    pccb = minter.mint(intent, decision, context)

    # Warmup
    for _ in range(50):
        verifier.verify(intent, pccb, context)

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        verifier.verify(intent, pccb, context)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)

    times.sort()
    return {
        "path": "asymmetric (Ed25519)",
        "iterations": iterations,
        "p50_ms": times[len(times) // 2],
        "p99_ms": times[int(len(times) * 0.99)],
        "mean_ms": statistics.mean(times),
        "throughput_per_sec": 1000.0 / statistics.mean(times),
    }


def main() -> int:
    import platform

    print("=== Actenon Kernel Verification Benchmark ===")
    print(f"Python: {platform.python_version()}")
    print(f"Platform: {platform.platform()}")
    print(f"Processor: {platform.processor() or 'unknown'}")
    print()

    iterations = 1000

    print(f"--- Symmetric (HMAC) path, {iterations} iterations ---")
    sym = benchmark_symmetric(iterations)
    print(f"  p50: {sym['p50_ms']:.3f} ms")
    print(f"  p99: {sym['p99_ms']:.3f} ms")
    print(f"  mean: {sym['mean_ms']:.3f} ms")
    print(f"  throughput: {sym['throughput_per_sec']:.0f}/s per core")
    print()

    print(f"--- Asymmetric (Ed25519) path, {iterations} iterations ---")
    asym = benchmark_asymmetric(iterations)
    if asym:
        print(f"  p50: {asym['p50_ms']:.3f} ms")
        print(f"  p99: {asym['p99_ms']:.3f} ms")
        print(f"  mean: {asym['mean_ms']:.3f} ms")
        print(f"  throughput: {asym['throughput_per_sec']:.0f}/s per core")
    else:
        print("  (skipped — cryptography not installed)")
    print()

    # Memory footprint
    try:
        import resource
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(f"--- Memory footprint ---")
        print(f"  RSS: {rss_kb / 1024:.1f} MB")
    except Exception:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
