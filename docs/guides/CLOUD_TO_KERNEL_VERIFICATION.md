# Cloud To Kernel Verification

This guide describes the first cross-repo conformance vector proving that an
Actenon Cloud invoice-payment proof can be verified by the open Actenon Kernel.

The vector lives at:

```text
conformance/vectors/cloud_invoice_payment_v1/
```

It contains:

- `action_intent.json`: the kernel-shaped `ActionIntent`
- `pccb.json`: the Cloud-issued kernel `PCCB`
- `issuer_keys.json`: the Cloud well-known key-discovery document
- `receipt.json` and `refusal.json`: copied Cloud outcome artifacts
- `receipt_attestation.json` and `refusal_attestation.json`: signed outcome
  attestation envelopes whose signatures cover only `unsigned_payload`
- `mutations/`: negative vectors for changed amount, changed audience, changed
  expiry, changed action hash, changed signature, wrong key id, wrong key
  purpose, outcome artifact tampering, digest tampering, proof-binding
  tampering, issuer/issued-at tampering, and hard revoke

## Install

Install the kernel with asymmetric verification support:

```bash
pip install -e ".[asymmetric]"
```

The asymmetric extra is required because the vector uses an OKP/Ed25519 JWK and
a raw Ed25519 signature.

## Portable Cross-Repo Check

Actenon Cloud owns a portable verification script that installs the kernel from
a configurable checkout path, regenerates the vector, compares it to the
committed vectors in both repos, and then runs the kernel verification test:

```bash
export ACTENON_KERNEL_REPO="/path/to/actenon-verifier-kernel"
export ACTENON_CLOUD_REPO="/path/to/actenon-cloud"
export PYTHON=python3
bash "$ACTENON_CLOUD_REPO/scripts/verify_cloud_to_kernel.sh"
```

No workstation-local direct dependency such as `file:///Users/...` is required.
Cloud CI should check out both repos and install the kernel with:

```bash
python -m pip install -e "${ACTENON_KERNEL_REPO}[asymmetric]"
```

## Verification Path

The kernel integration test performs this path:

1. Cloud creates an invoice-payment Action Intent.
2. Cloud exports a real kernel-compatible PCCB.
3. Cloud signs the exact bytes from `PCCB.unsigned_payload()`.
4. Cloud publishes an OKP/Ed25519 JWK at `/.well-known/actenon/keys.json`.
5. The kernel resolves the issuer key through `WellKnownKeyResolver`.
6. The kernel verifies the PCCB signature, action hash, audience, subject,
   tenant, target, scope, and validity window.
7. Cloud emits receipt/refusal attestation envelopes with sibling
   `external_anchors`.
8. The kernel verifies each attestation with an `outcome_attestation` key,
   checks the embedded artifact digest, checks proof-binding consistency, and
   verifies the signature over `unsigned_payload`.

Fixture time is pinned. The PCCB is valid from `2026-01-15T12:00:00Z` through
`2026-01-15T12:15:00Z`, and the test uses `2026-01-15T12:05:00Z`.

## Negative Vectors

The kernel test also proves these failures:

- mutating the amount in `action_intent.json` fails verification
- mutating the PCCB audience fails verification
- mutating `expires_at` so the pinned context is outside the validity window
  fails with `PROOF_EXPIRED`
- mutating the PCCB action hash fails verification
- mutating the PCCB signature fails verification
- changing `signature.key_id` to an unknown key fails verification
- publishing the proof key with `use: outcome_attestation` fails proof
  verification
- tampering with the attested outcome artifact fails attestation verification
- tampering with the attestation artifact digest fails verification
- tampering with `proof_binding` fails verification
- tampering with the attestation signature fails verification
- tampering with `unsigned_payload.issuer` fails receipt/refusal attestation
  verification
- tampering with `unsigned_payload.issued_at` fails receipt/refusal attestation
  verification
- publishing the outcome key with `use: proof_issuance` fails attestation
  verification
- hard-revoking the outcome key without an external anchor fails historical
  attestation verification

For the local external-anchor primitive, see
[EXTERNAL_ANCHORS.md](EXTERNAL_ANCHORS.md).

The wrong-purpose case is important: a PCCB must verify only against a key whose
well-known entry is authorized for `proof_issuance`, and a receipt/refusal
attestation must verify only against a key authorized for `outcome_attestation`.

## Cloud Generation

Actenon Cloud owns the deterministic vector generator:

```bash
python scripts/generate_cloud_invoice_payment_vector.py \
  --output conformance/vectors/cloud_invoice_payment_v1
```

The Cloud contract test regenerates the bundle and compares it to the committed
vector. That makes drift visible before the kernel-side verification fixture is
updated.

## Current Scope

This pass proves external verifiability of the Cloud-issued invoice-payment
PCCB and the copied Cloud receipt/refusal attestation envelopes.

Receipt/refusal attestation verification proves origin and integrity of the
attestation `unsigned_payload`, the embedded artifact digest, and the
proof-binding references that are present in the embedded outcome artifact. It
does not prove business correctness, provider finality, replay protection,
protected-endpoint enforcement, downstream adapter correctness, hosted approval
correctness, or that Cloud should have emitted the outcome.

The controlling doctrine for this path is:

- [../../REVOCATION_AND_RECEIPT_DURABILITY.md](../../REVOCATION_AND_RECEIPT_DURABILITY.md)
- [../../CROSS_REPO_WIRE_CONTRACTS.md](../../CROSS_REPO_WIRE_CONTRACTS.md)
- [CANONICALIZATION_AND_INTEROP.md](CANONICALIZATION_AND_INTEROP.md)

The keystone proves external verifiability of issued proof and outcome
artifacts. It does not, by itself, prove replay protection, protected-endpoint
enforcement, downstream adapter correctness, or business-policy correctness.
