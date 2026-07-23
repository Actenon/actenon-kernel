# Transparency Log Proof Format

Status: Active opt-in v1 public verification surface

## Purpose

This specification defines portable, offline-verifiable transparency artifacts
for receipt digests:

- a signed checkpoint, also called a signed tree head
- a Merkle inclusion proof
- an append-only consistency proof between checkpoints

The formats and verifier routines are public so a relying party can detect an
orphan counter-signature, log rewind, or inconsistent history without trusting
the operator that runs the log.

This specification does not define or ship a running transparency-log service,
private signing keys, submission APIs, availability guarantees, or storage.

Machine schemas:

- [`../../schemas/transparency_checkpoint.v1.json`](../../schemas/transparency_checkpoint.v1.json)
- [`../../schemas/transparency_inclusion_proof.v1.json`](../../schemas/transparency_inclusion_proof.v1.json)
- [`../../schemas/transparency_consistency_proof.v1.json`](../../schemas/transparency_consistency_proof.v1.json)

## Merkle Tree

The v1 tree uses SHA-256 with RFC 6962-style domain separation.

For a Receipt artifact digest `D`, where `D` is the 32 bytes decoded from its
lowercase hexadecimal digest:

```text
LeafHash(D) = SHA-256(0x00 || D)
NodeHash(L, R) = SHA-256(0x01 || L || R)
```

The artifact digest itself remains:

```text
SHA-256(RFC8785-JCS(artifact))
```

Tree construction and proof ordering follow RFC 6962 Merkle audit and
consistency proof semantics. Odd subtrees are promoted; implementations must
not duplicate the final leaf.

## Signed Checkpoint

```json
{
  "contract": {
    "name": "transparency_checkpoint",
    "version": "v1"
  },
  "log": {
    "type": "transparency_log",
    "id": "example-log"
  },
  "tree_size": 4,
  "root_hash": {
    "algorithm": "sha-256",
    "encoding": "hex",
    "value": "<64 lowercase hex characters>"
  },
  "issued_at": "2026-06-06T12:00:00Z",
  "signature": {
    "algorithm": "EdDSA",
    "key_id": "log-checkpoint-2026-06",
    "encoding": "base64url",
    "value": "<unpadded base64url Ed25519 signature>"
  }
}
```

The Ed25519 signature covers the RFC 8785 canonical bytes of:

```json
{
  "context": "actenon.transparency-checkpoint.v1",
  "log": "<the complete log identity>",
  "tree_size": 4,
  "root_hash": "<the complete root hash object>",
  "issued_at": "<the exact checkpoint timestamp>"
}
```

Checkpoint public keys use `key_discovery v1` with:

```json
{
  "algorithm": "EdDSA",
  "use": "transparency_checkpoint",
  "key_id": "<kid>",
  "status": "active"
}
```

Verification selects the exact key by `kid`, checks its purpose and time bounds,
and requires the key-set issuer to match `checkpoint.log`.

## Inclusion Proof

```json
{
  "contract": {
    "name": "transparency_inclusion_proof",
    "version": "v1"
  },
  "log_id": "example-log",
  "hash_algorithm": "sha-256",
  "tree_size": 4,
  "leaf_index": 2,
  "leaf_digest": {
    "algorithm": "sha-256",
    "canonicalization": "RFC8785-JCS",
    "value": "<artifact digest>"
  },
  "audit_path": [
    "<sibling hash nearest the leaf>",
    "<next sibling hash toward the root>"
  ]
}
```

`audit_path` is ordered from the leaf toward the root. Verification requires
the proof log, tree size, and recomputed root to match the supplied checkpoint.

## Consistency Proof

```json
{
  "contract": {
    "name": "transparency_consistency_proof",
    "version": "v1"
  },
  "log_id": "example-log",
  "hash_algorithm": "sha-256",
  "old_tree_size": 2,
  "new_tree_size": 4,
  "consistency_path": [
    "<ordered RFC 6962 consistency hash>"
  ]
}
```

A valid proof demonstrates that the old tree is a prefix of the new tree.
Verification fails when:

- the new tree size is smaller
- same-size checkpoints have different roots
- either checkpoint identifies a different log
- the proof does not reconstruct both roots
- the proof contains missing or extra hashes

## Counter-Signature Anchor Profile

A `receipt_countersignature v1` artifact can identify its log leaf using:

```json
{
  "anchor_reference": {
    "type": "transparency_log",
    "id": "example-log",
    "leaf_index": 2
  }
}
```

`verify_countersignature_inclusion` requires:

1. a valid signed checkpoint
2. a valid inclusion proof for the counter-signature's exact `receipt_digest`
3. exact equality between the anchor log identifier and proof log identifier
4. exact equality between the anchor leaf index and proof leaf index

This check is additive to `verify_countersignature`. Relying parties should
verify both the counter-signature and its log inclusion. A signature with no
matching verified inclusion proof is an orphan and must be rejected when log
anchoring is required.

## Independent Monitoring

An independent monitor stores the last trusted checkpoint and, for each update:

1. verifies both checkpoint signatures against pinned public keys
2. rejects a smaller tree size as rewind
3. rejects a same-size different root as equivocation
4. verifies the consistency proof for every larger tree
5. persists the new checkpoint only after all checks pass
6. compares checkpoints with other monitors or witnesses

The SDK routine `verify_monitor_update` implements steps 1 through 4 without
network access. Fetching, durable state, gossip, alerting, and cross-monitor
exchange remain deployment choices.

Python example:

```python
from actenon.verifier import verify_monitor_update

verified = verify_monitor_update(
    previous_checkpoint,
    current_checkpoint,
    consistency_proof,
    pinned_public_keys,
)
```

The monitor MUST persist `verified.current` only after this call succeeds. A
monitor that overwrites its last trusted checkpoint before verification cannot
reliably detect rewind. Independent monitors SHOULD exchange the tuple
`(log.type, log.id, tree_size, root_hash)`; two valid signed checkpoints for
the same log and tree size with different roots are split-view evidence.

## Security And Claim Boundary

Successful verification proves only:

- a trusted checkpoint key signed the stated tree root and size
- the supplied digest is included in that tree, when inclusion verifies
- the newer tree is an append-only extension of the older tree, when
  consistency verifies

It does not prove:

- that the underlying Receipt is truthful
- that every artifact was submitted to the log
- that the log was available to every party
- provider finality or production exposure
- absence of a split view unless monitors compare checkpoints

Transparency makes equivocation detectable when independently observed
checkpoints are compared. It does not make a dishonest log impossible.

## Compatibility

Changing the domain-separation bytes, leaf input, node hashing, proof ordering,
checkpoint signature input, contract names, or required fields requires a new
format version.
