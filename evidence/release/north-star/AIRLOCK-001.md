# AIRLOCK-001 — NOT STARTED

Instruction: "Do not begin AIRLOCK-001 until G1–G5 are genuinely PASS against released artefacts."

State on 2026-10-03: no candidate has been published (RELEASE GATE READY, stopped before the first
publication), so G1, G2 and G4 cannot be PASS against released artefacts (FINAL-GATES.md).
AIRLOCK-001 has therefore not been started.

When the release graph has completed and FINAL-GATES.md shows G1–G5 PASS against the published artefacts,
AIRLOCK-001 starts as a frozen programme. Its scope and acceptance criteria are written and committed before
any run. It includes the two regressions this work found and fixed on the candidates:

- **glob scope:** a `payments.*` grant yields exact-capability proofs that verify, and no wider capability.
  Covered today by E2E E0 on four edges.
- **revoked proof:** a proof minted before its grant (or an ancestor) is revoked is refused
  (`AUTHORITY_REVOKED`), and an unknown or unreachable revocation source fails closed. Covered today by E2E
  E8b–E8e on four edges.
