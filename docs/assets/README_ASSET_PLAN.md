# README Asset Plan

Required launch asset:

- `docs/assets/actenon-hero-demo.gif`

The GIF should show the first README demo path:

1. an agent-controlled destructive or high-impact action is attempted
2. Actenon verifies the proof at the execution boundary
3. the mutated action is refused with `ACTION_HASH_MISMATCH`
4. a Refusal artifact is emitted and opened briefly

Constraints:

- do not imply Actenon Network, Agent Trust Score, production KMS/HSM custody,
  insurer endorsement, or regulator recognition exists
- keep incident wording as educational pattern reconstruction
- show local OSS kernel behavior only
- keep terminal text legible at GitHub README width
