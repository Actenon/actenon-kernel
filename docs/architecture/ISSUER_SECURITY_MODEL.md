# Issuer Security Model

Status: issuer/control-plane security doctrine. This document clarifies the proof root and signing-custody responsibilities. It does not change PCCB semantics or implement a hosted control plane.

## Issuer Is The Proof Root

The issuer or control plane decides whether proof may exist. Its signing key is the root of proof issuance trust for verifiers that trust that issuer.

The Protected Endpoint can verify:

- issuer
- key id and algorithm
- signature over canonical bytes
- tenant
- subject/requester
- audience
- action and target
- scope/capabilities
- validity window
- nonce or single-use identifier
- replay/escrow state where used

The Protected Endpoint cannot infer that the upstream business decision was correct if the issuer or control plane signed the wrong action.

## Production Issuer Requirements

A production issuer must:

- use non-exportable asymmetric signing keys
- use KMS/HSM-backed custody or equivalent managed custody
- separate `proof_issuance` keys from `outcome_attestation` keys
- deny by default
- bind approval/evidence references or digests into proof/outcome records where used
- publish public verification material through well-known JWK discovery
- maintain key lifecycle state and timestamps
- record audit metadata for every signing attempt
- protect signing operations with operator and service identity controls
- minimize who or what can request proof issuance

Local and pilot signers are useful for tests and design-partner pilots. They are not production issuer custody.

## Issuer Input Model

Before signing, the issuer should evaluate:

- tenant
- subject/requester
- audience
- action and target
- requested scope/capabilities
- consequence class
- policy decision
- evidence and approval state
- request id and correlation id
- expiry and not-before windows
- replay or escrow requirements

The signed proof should bind the exact action the Protected Endpoint will verify. Free-floating approvals are not enough if the final executor can act on different parameters.

## Key Purposes

Use purpose-separated keys:

- `proof_issuance`: signs PCCBs or equivalent proof artifacts used to authorize protected execution
- `outcome_attestation`: signs copied Receipt/Refusal attestation envelopes

A key configured for one purpose must not sign the other purpose. Purpose mismatch must fail closed.

## Audit Model

Every signing attempt should produce an operation audit record, including failed attempts. The record should include:

- operation id
- tenant id
- issuer id
- key id
- key purpose
- algorithm
- backend
- provider operation reference where available
- payload digest
- request id
- correlation id
- actor or service identity
- status and failure reason
- timestamp

Audit records should avoid raw action parameters unless policy explicitly requires them. They must not include private keys, raw provider credentials, or secret material.

## Compromise Assumptions

If the issuer key or control plane is compromised, a malicious actor may cause valid proof to be minted for the wrong action. Actenon cannot make that proof operationally correct after the fact.

Mitigations belong around the issuer:

- production-grade signing custody
- key purpose separation
- short proof validity windows
- separation of duties for high-impact issuance
- approval/evidence binding
- mint audit logging
- anomaly detection
- fast suspend/revoke/hard-revoke operations
- external anchoring for historical recovery when needed

## What Verifiers Trust

Verifiers trust configured issuer origins, discovered public key material, key purpose, key lifecycle state, and local verification policy. They do not trust the agent.

If key discovery, signature verification, lifecycle checks, audience binding, action binding, expiry, replay, or required escrow cannot be verified, the verifier or Protected Endpoint must refuse.

