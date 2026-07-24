# Failure Modes

> Every failure mode, with detection method, blast radius, and operator
> action. This is the document a platform team asks for and never gets.

| Failure mode | Detection | Blast radius | Operator action |
|---|---|---|---|
| **Replay store unreachable** | `actenon_replay_store_errors_total` metric > 0; `claim_request()` raises | All consequential actions refused (fail-closed). Payment path stops. | 1. Check DB connectivity. 2. Check network. 3. If store is down, restore from backup. 4. Gate resumes automatically when store recovers. |
| **Signing key compromise** | Audit log shows unexpected proof issuance; external indicator | All proofs minted by the compromised key are suspect. | 1. Rotate the key (see KMS_ROTATION_RUNBOOK.md). 2. Mark old key as `revoked`. 3. If historical verifiability must be broken, mark as `hard_revoked` (requires external anchor). |
| **Clock skew exceeded** | `PROOF_NOT_YET_VALID` or `PROOF_EXPIRED` refusal rate spikes | Valid proofs refused. Agents cannot execute. | 1. Check NTP on verifier host. 2. Correct clock drift. 3. Consider temporarily increasing `clock_skew_tolerance` (security trade-off). |
| **Well-known key fetch failure** | `KeyDiscoveryFetchError` in logs; `SIGNATURE_INVALID` refusals | Verifier cannot resolve new keys; proofs signed by new keys are refused. | 1. Check network to issuer's `.well-known/actenon/keys.json`. 2. If issuer is down, provision keys inline (see §1.2 of PRODUCTION_INTEGRATION.md). 3. Consider switching to inline key provisioning for production. |
| **Replay store corruption** | SQLite/Postgres error on claim; `OperationalError` | All actions refused (fail-closed). | 1. Stop the verifier. 2. Restore the replay DB from backup. 3. If no backup, the replay state is lost — all in-flight proofs will need re-issuance. 4. Restart. |
| **Proof minter unavailable** | Issuer health check fails | No new proofs can be minted. Existing valid proofs still verify and execute. | 1. Check minter service health. 2. If minter is down, break-glass procedure (see actenon-cloud/docs/BREAK_GLASS_RUNBOOK.md — but note: that doc is source-available; the OSS equivalent is to pre-mint proofs for critical actions). 3. Restore minter. |
| **Verifier memory exhaustion** | OOM kill; verifier process restarts | Brief unavailability; in-flight requests fail. | 1. Check for memory leak (file an issue). 2. Increase memory limit. 3. Restart verifier. |
| **Disk full (SQLite replay)** | `OperationalError: disk I/O error` | All actions refused (fail-closed). | 1. Free disk space. 2. Prune old replay keys. 3. Consider migrating to Postgres for production. |
| **Canonicalisation failure** | `CANONICALISATION_FAILURE` refusal | Specific proof refused; other proofs unaffected. | 1. Check the proof's payload for unsupported types (sets, bytes, NaN). 2. Re-issue the proof with a valid payload. |
| **Audience mismatch** | `AUDIENCE_MISMATCH` refusal | Specific proof refused. | 1. Check the proof's `audience` field matches the verifier's configured audience. 2. Re-issue with correct audience. |
| **Action hash mismatch** | `SIGNATURE_INVALID` refusal (mutation detected) | Specific proof refused. | 1. Check the proof was not mutated in transit. 2. Re-issue the proof. 3. If mutation is unexpected, investigate the transport layer. |
| **PCCB expired** | `PROOF_EXPIRED` refusal | Specific proof refused. | 1. Re-issue the proof with a longer `expires_at`. 2. Check clock skew. |
| **Escrow record missing** | `EscrowRecord` lookup fails | Specific proof refused. | 1. Check the escrow store. 2. Re-create the escrow record. 3. Re-issue the proof. |
| **Revocation checker unavailable** | If configured, `AUTHORITY_REVOKED` or timeout | If checker is down, verifier may fail closed (depending on configuration). | 1. Check revocation checker service. 2. If checker is down, consider temporarily disabling revocation checking (security trade-off). |
