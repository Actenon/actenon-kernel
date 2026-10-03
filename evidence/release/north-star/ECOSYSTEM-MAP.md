# Actenon ecosystem map

Generated from `ECOSYSTEM-MAP.json` by `render_ecosystem_map.py` (collected live by `collect_ecosystem_map.py`).

| Repo | Remote | Branch / HEAD | Candidate | Dirty | Published now | Intended | Actenon deps | Release role | Gate-critical |
|---|---|---|---|---|---|---|---|---|---|
| **actenon-protocol** | https://github.com/Actenon/actenon-protocol | ross/keen-fermi-e2y72j `45b7753` | `45b7753` | 0 | pypi:actenon-protocol: 1.3.0<br>npm:@actenon/protocol-types: 1.3.0<br>npm:@actenon/protocol: not published (HTTP Error 404: Not Found) | 1.4.0 | none | step 1 (parallel with kernel) | G1, G2, G4 |
| **actenon-kernel** | https://github.com/Actenon/actenon-kernel | ross/keen-fermi-e2y72j `142364f` | `142364f` | 0 | pypi:actenon-kernel: 1.2.1<br>npm:@actenon/verifier-sdk: not published (HTTP Error 404: Not Found) | 1.3.0 (+ @actenon/verifier-sdk 0.2.0) | actenon-protocol>=1.1.0,<2 | step 2 — security floor for everything downstream | G1, G2, G3, G4, G5, G6 |
| **sdk-go** | https://github.com/Actenon/sdk-go | ross/keen-fermi-e2y72j `e3649cd` | `e3649cd` | 0 | go:github.com/Actenon/sdk-go: v1.0.0 | v1.1.0 | vendored kernel vectors (fixtures/KERNEL_PIN) | step 3 (after kernel release) | G1, G2, G4, G5 |
| **sdk-rust** | https://github.com/Actenon/sdk-rust | ross/keen-fermi-e2y72j `0a16a84` | `0a16a84` | 0 | crates:actenon-verifier-sdk: not published (HTTP Error 404: Not Found) | 0.2.0 | vendored kernel vectors (fixtures/KERNEL_PIN) | step 3 (after kernel release) | G1, G2, G4, G5 |
| **actenon-permit** | https://github.com/Actenon/actenon-permit | ross/keen-fermi-e2y72j `a5467ab` | `a5467ab` | 0 | pypi:actenon-permit: 1.4.0<br>npm:@actenon/sdk: 1.4.0 | 2.0.0 (+ @actenon/sdk 2.0.0) | actenon-kernel[asymmetric]>=1.3.0rc1,<2; actenon-protocol>=1.1.0,<2 | step 4 (after kernel on PyPI) | G1, G2, G3, G4, G6 |
| **blastradius** | https://github.com/Actenon/blastradius | main `df10b55` | `d7f60a6` | 0 | pypi:actenon-blastradius: 0.4.0 | 0.5.0 | none | step 5 (independent) | G2 (own CI) |
| **.github** | https://github.com/Actenon/.github | main `f8317f6` | `—` | 0 | — | — | none | none (documentation claims only) | G4 (public claims) |

## Runtime roles

- **actenon-protocol**: wire contract: canonicalisation, refusal catalogue, schemas, protocol docs (13 edge binding)
- **actenon-kernel**: reference verifier + protected executor (single use, replay store, edge binding, revocation); TS verifier SDK
- **sdk-go**: Go verifier SDK (verify only; integrator enforces single use)
- **sdk-rust**: Rust verifier SDK (verify only)
- **actenon-permit**: authority broker: grants, PDP, Ed25519 proof minting, gateway, revocation source
- **blastradius**: independent shell-command guard (no Actenon runtime dependency)
- **.github**: org profile / community health files

## Workflows (from the candidate checkout)

### actenon-protocol
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| actenon-scan.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `scan` → scan |  |
| ci.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": {"branches": ["main", "master"]}, "workflow_dispatch": null}` | `conformance` → Conformance suite (Python ${{ matrix.python-version }}); `lint` → Lint + format check; `typescript` → TypeScript types check; `typescript-runtime` → TypeScript runtime (@actenon/protocol) |  |
| link-check.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `lychee` → lychee |  |
| publish-ts-runtime.yml | `{"push": {"tags": ["ts-runtime-v*"]}, "workflow_dispatch": null}` | `verify` → Build + test @actenon/protocol; `publish` → Publish to npm with provenance | **yes** |
| publish-ts-types.yml | `{"push": {"tags": ["ts-types-v*"]}, "workflow_dispatch": null}` | `verify` → Build + test @actenon/protocol-types; `publish` → Publish to npm | **yes** |
| publish.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `build` → build; `publish` → publish | **yes** |
| verify-claims.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "41 6 * * *"}], "workflow_dispatch": null}` | `verify-claims` → Verify README claims (machine-enforced) |  |
| version-coherence.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "23 6 * * *"}], "workflow_dispatch": null}` | `version-coherence` → pyproject / tag / PyPI agree |  |

### actenon-kernel
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| actenon-scan.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `scan` → scan |  |
| bandit.yml | `{"push": {"branches": ["main"], "paths": ["actenon/**", ".github/workflows/bandit.yml"]}, "pull_request": {"paths": ["actenon/**", ".github/workflows/bandit.yml` | `bandit` → Bandit scan (actenon/, severity >= medium, gating) |  |
| ci.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": {"branches": ["main", "master"]}}` | `test` → Python tests (${{ matrix.python-version }}); `postgres-replay` → Replay store on PostgreSQL 16; `typescript-verifier` → TypeScript verifier SDK; `go-verifier` → Go verifier SDK (standalone, pinned); `rust-verifier` → Rust verifier SDK (standalone, pinned) |  |
| conformance-release.yml | `{"push": {"tags": ["conformance-v*"]}}` | `release` → Signed conformance vectors |  |
| invariants.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": null}` | `invariant-tests` → Invariant tests; `clean-install` → Clean-install closure check; `base-install-conformance` → Base-install conformance (no extras) |  |
| link-check.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `lychee` → lychee |  |
| protocol-drift.yml | `{"push": {"branches": ["main"]}, "pull_request": null, "schedule": [{"cron": "0 4 * * *"}]}` | `drift-gate` → drift-gate |  |
| publish-mcp-registry.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `publish-mcp-registry` → List actenon-kernel in the MCP Registry | **yes** |
| publish.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `build` → build; `publish` → publish | **yes** |
| supply-chain.yml | `{"push": {"branches": ["main", "master"], "tags": ["v*"]}, "pull_request": null}` | `sbom` → Generate SBOM (CycloneDX); `pip-audit` → Audit dependencies (pip-audit); `sigstore-release` → Sigstore-sign release wheel |  |
| verify-claims.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "47 6 * * *"}], "workflow_dispatch": null}` | `verify-claims` → Verify README claims (machine-enforced) |  |
| verify-published.yml | `{"schedule": [{"cron": "17 5 * * 1"}], "workflow_dispatch": null}` | `verify` → Published ${{ matrix.artefact }} |  |
| version-coherence.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "23 6 * * *"}], "workflow_dispatch": null}` | `version-coherence` → pyproject / tag / PyPI agree |  |

### sdk-go
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| actenon-scan.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `scan` → scan |  |
| ci.yml | `{"push": {"branches": ["main"]}, "pull_request": null}` | `test` → Test (Go ${{ matrix.go-version }}); `kernel-vectors` → Vendored kernel vectors match the pinned kernel |  |

### sdk-rust
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| ci.yml | `{"push": {"branches": ["main"]}, "pull_request": null}` | `lint` → fmt + clippy + doc; `test` → Test (Rust ${{ matrix.rust }}); `kernel-vectors` → Vendored kernel vectors match the pinned kernel |  |
| publish.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `publish` → Publish to crates.io | **yes** |

### actenon-permit
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| actenon-scan.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `scan` → scan |  |
| ci.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": {"branches": ["main", "master"]}, "schedule": [{"cron": "0 3 * * *"}]}` | `test-python` → test-python; `kernel-conformance` → kernel-conformance; `test-ts` → test-ts; `live-compat` → live-compat |  |
| link-check.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "0 6 * * *"}]}` | `lychee` → lychee |  |
| protocol-drift.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": null, "schedule": [{"cron": "0 4 * * *"}]}` | `drift-gate` → drift-gate |  |
| publish-ts-sdk.yml | `{"push": {"tags": ["ts-sdk-v*"]}, "workflow_dispatch": null}` | `build` → Build @actenon/sdk; `publish` → Publish to npm | **yes** |
| publish.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `build` → build; `publish` → publish | **yes** |
| verify-claims.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "53 6 * * *"}], "workflow_dispatch": null}` | `verify-claims` → Verify README claims (machine-enforced) |  |
| version-coherence.yml | `{"pull_request": null, "push": {"branches": ["main"]}, "schedule": [{"cron": "23 6 * * *"}], "workflow_dispatch": null}` | `version-coherence` → pyproject / tag / PyPI agree |  |

### blastradius
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|
| ci.yml | `{"push": {"branches": ["main", "master"]}, "pull_request": {"branches": ["main", "master"]}}` | `test` → Python tests (${{ matrix.python-version }}) |  |
| publish.yml | `{"push": {"tags": ["v*"]}, "workflow_dispatch": null}` | `build` → build; `publish` → publish | **yes** |

### .github
| File | Triggers | Jobs (id → displayed name) | Publishes |
|---|---|---|---|

## Outside the release graph

- **actenon-scan**: CI-time dependency only (kernel/permit/protocol/sdk-go run actenon-scan.yml); dev-only dep on actenon-protocol; NOT modified (standing instruction from phase 1)
- **actenon-cloud**: private, optional managed control plane; not a dependency of any public component; no private data recorded here

## Branch protection expectations

See `CI-GATE-MATRIX.md` (exact required check names, verified against GitHub check-run names).
