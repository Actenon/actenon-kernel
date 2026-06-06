# Refusal Message Hygiene

Actenon refusals expose a stable `reason_code` and a short public message.
The code is the machine-readable diagnostic. The message explains the failed
class of check without echoing attacker-controlled or sensitive material.

## Public Message Rules

Proof-verification refusal messages may identify:

- the failed validation class
- whether the failure concerns time, audience, scope, binding, hash, or signature
- whether retrying with a newly issued proof may be appropriate

They must not include:

- raw proof or signature material
- expected or supplied hashes
- tenant, subject, target, audience, or key identifiers
- credential material or secrets
- trust-store contents
- provider, parser, crypto-library, or stack-trace text
- handler exception messages

Python proof-verification messages are defined in
`actenon.proof.PUBLIC_PROOF_REFUSAL_MESSAGES`. The shared verifier SDK
conformance vectors assert the same reason code and message in Python,
TypeScript, Go, and Rust.

## Structured Details

Public refusal details may contain documented, non-secret remediation fields,
such as unmet policy requirements or a request correlation identifier.
Unexpected handler/provider exceptions use a safe error code and redacted
metadata. Raw exception text stays out of Receipt and Refusal artifacts.

Deployments that need deeper diagnostics should send them to a separately
access-controlled operational sink keyed by a correlation ID. They should not
make the public artifact more revealing.

## Compatibility

`reason_code` is the canonical Python and JSON field. The deprecated Python
`refusal_code` alias exists only for one-release compatibility and must not be
serialized into new artifacts.

## Verification

Run:

```bash
python3 -m pytest tests/unit/test_refusal_message_hygiene.py -q
bash scripts/verify_sdk_conformance.sh
```
