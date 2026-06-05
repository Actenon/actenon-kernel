# Canonicalization And Interop

Actenon Cloud and the open kernel must sign and verify byte-identical payloads.
The v2 keystone therefore treats canonicalization as a trust boundary, not an
internal helper.

Install the kernel with asymmetric verification support when testing
cross-boundary EdDSA artifacts:

```bash
pip install -e ".[asymmetric]"
```

Core kernel installs remain dependency-minimal. The `asymmetric` extra is
required only for well-known Ed25519/EdDSA verification through the Python
kernel path.

## Frozen Profile

Cross-repo artifacts use:

```yaml
canonicalization_profile: "actenon-jcs-sha256-v1"
```

The profile freezes:

- deterministic JSON canonicalization
- SHA-256 digests
- rejection of floating-point values
- deterministic string escaping and Unicode handling
- explicit duplicate-key vector behavior
- base64url without padding where base64url is required
- no in-place profile changes

Duplicate JSON object keys are invalid. Runtime parsers must reject them before
canonicalization rather than accepting whichever value a platform parser keeps.

The Python kernel also applies default verification limits before or during
canonicalization: raw JSON inputs up to 1,048,576 bytes, JSON-like values up to
128 nesting levels, and canonicalized JSON output up to 1,048,576 bytes.
Oversize or deeply nested inputs fail closed.

Any future change requires a new canonicalization profile version, a
dual-support window, and conformance vectors for both versions.

## Public Kernel Helpers

Cloud and other issuers must use the kernel helpers for public proof export:

- `actenon.proof.canonicalize_json`
- `actenon.proof.canonicalize_bytes`
- `actenon.proof.sha256_hex`
- `actenon.proof.build_action_hash_input`
- `PCCB.unsigned_payload()`

Using `json.dumps(sort_keys=True)` is not a cross-repo contract. It can appear
in logs or non-security-local formatting, but it must not be the signing or
digest contract for Cloud-issued public artifacts.

## PCCB Signing Rule

Cloud internal `IssuedProof` records are not PCCBs. For external verification,
Cloud must export a real kernel-compatible PCCB and sign:

```python
canonicalize_bytes(pccb.unsigned_payload())
```

The verifier recomputes the same unsigned payload and validates the signature
against the issuer key discovered from `/.well-known/actenon/keys.json`.

## Action Hash Rule

Cloud must use the same action-hash input structure as the kernel:

```python
build_action_hash_input(intent)
```

Shared canonicalization is necessary but not sufficient. If Cloud builds a
different dictionary before canonicalization, the proof can still fail kernel
verification.

## Scope

This guide covers canonical bytes and digest compatibility. It does not claim
replay protection, protected-endpoint enforcement, downstream adapter
correctness, or business-policy correctness.
