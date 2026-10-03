# Full E2E on rehearsal 3 — two harness attempts before the final run (preserved)

| Attempt | Stopped at | Class | Fix |
|---|---|---|---|
| 1 | building go_edge: `modernc.org/sqlite@v1.60.1 requires go >= 1.26.0 (running go 1.24.7; GOTOOLCHAIN=local)` | HARNESS (third-party SQLite driver used only by the Go edge program to read Permit's store; not an Actenon artefact) | pin `modernc.org/sqlite@v1.38.2` (go 1.23) |
| 2 | `initdb: could not access directory …/scratchpad/…: Permission denied` | HARNESS (the server runs as `postgres`, which cannot traverse the root-only TMPDIR) | cluster under its own `/tmp/actenon-e2e-pg.*` |
| final | — | 25/25 on SQLite replay, 25/25 on PostgreSQL 16; 14 three-edge sites × {ts, go, rust} all ran | — |
