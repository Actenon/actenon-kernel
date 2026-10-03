# Permit PR #11: 2.0.0 or 1.5.0? (re-determined 2026-10-02T18:3xZ)

Independent re-run. The 09:39Z determination on the orphan branch
`evidence/north-star-20261002` (`05-release/PERMIT-VERSION-DETERMINATION.md`) was **not** reused as
evidence. Its conclusion is reproduced below from fresh artefacts.

## Artefacts
- PR #11 head `ef20ad7` (`fix/canonicalisation-unification`, base `ed0a68e`, **11 commits behind** main `c1eea9c`).
  Wheel built with `uv build --wheel` from `git archive ef20ad7` into a clean py3.11 venv. Installed version: `actenon-permit 2.0.0`
  (with kernel 1.2.1 and protocol 1.3.0 from PyPI).
- Released `actenon-permit==1.4.0` from PyPI in a separate clean venv.
- `@actenon/sdk@1.4.0` from npm into an empty directory. Executed under node v22.22.0 and bun 1.3.14.
- One shared HMAC key (`ACTENON_SIGNING_KEY`). Three grants: ASCII `agent_id`, non-ASCII `agent_id`, `Decimal("0.10")` budget.
- Scripts: `mint.py`, `verify_py.py`, `verify_ts.mjs`. Tokens: `tokens-permit-1.4.0.json`, `tokens-permit-pr11-ef20ad7.json`.
- Raw output: `results-python.txt`, `results-ts.txt`.

## The compatibility contract Permit states (main `c1eea9c`)
- `SPEC.md` §9: future versions "MUST NOT change the meaning of existing fields" and "MUST NOT … change the
  canonical-JSON rule"; "A future `version` field will be added when the format diverges non-additively."
- `canonical_json`, `grant_to_token` and `token_to_grant` are exported in `actenon_permit.__all__` (public API).
- Version ≥ 1.0.0, so SemVer applies. Permit documents **no** security-fix exception like kernel `VERSIONING.md` §1.4.

## Observed (raw lines in the results files)

| producer → verifier | ascii | non_ascii | decimal |
|---|---|---|---|
| permit 1.4.0 → permit 1.4.0 (py) | ACCEPT | ACCEPT | ACCEPT |
| **PR #11 (2.0.0) → permit 1.4.0 (py)** | **REJECT** unsupported token version | **REJECT** | **REJECT** |
| permit 1.4.0 → PR #11 (py) | ACCEPT | ACCEPT | ACCEPT |
| PR #11 → PR #11 (py) | ACCEPT | ACCEPT | ACCEPT |
| permit 1.4.0 → @actenon/sdk 1.4.0 (bun) | ACCEPT | **REJECT** signature mismatch | ACCEPT |
| **PR #11 → @actenon/sdk 1.4.0 (bun)** | **REJECT** unsupported token version | **REJECT** | **REJECT** |
| any → @actenon/sdk 1.4.0 (node ESM) | import fails: `ERR_MODULE_NOT_FOUND` (`dist/protocol` without `.js`) | | |

- `canonical_json({"a": 1.5})`: 1.4.0 returns `'{"a":1.5}'`. PR #11 **raises** `CanonicalisationError`.
- PR #11 changes no file under `ts-sdk/` (diff stat: CHANGELOG, pyproject, `__init__`, ledger, model, token, 3 test files).

## Determination
1. **PR #11 is a MAJOR change. 2.0.0 is correct. 1.5.0 is rejected.** Three independent breaks:
   - (a) A producer change makes new tokens unreadable by every released consumer (Python 1.4.0 and TS 1.4.0).
   - (b) A public function (`canonical_json`) changes from returning to raising for inputs it accepted.
   - (c) The canonical-JSON rule changes, which SPEC §9 forbids within the format version. PR #11 versions it via the
     `v2.` prefix and the ledger `chain_version`.

   Releasing this as 1.5.0 would silently downgrade a breaking change.
2. **PR #11 is not releasable as written, even as 2.0.0.**
   - Permit's own TS SDK (`@actenon/sdk`) cannot read the tokens the 2.0.0 broker mints. PR #11 does not update
     `ts-sdk/src/token.ts`.
   - The PR is 11 commits behind main.
   - Permit CI (`ci.yml`) is `disabled_inactivity`, so PR #11 has never been gated on GitHub.
3. A 1.5.0 would be correct only for a *different* change: accept `v2.` while still minting `v1.`, and keep
   `canonical_json` unchanged with a new strict function beside it. That would leave the non-ASCII TS defect in place
   for default-minted grants, so it is not equivalent to PR #11.
4. The secure-defaults work (kernel candidate) changes Permit's behaviour **through its kernel dependency**. On
   kernel 1.3.0rc1, with no key configured and `ACTENON_ENV` unset, `resolve_signer()` now raises instead of signing with
   the public secret. Permit must either declare development intent for its demos or require configuration. Whether
   that alone needs a Permit major depends on Permit's own contract, which says nothing about signer fallback; the
   owner decides. It does not change the PR #11 conclusion.

## Smallest path to a correct Permit 2.0.0 candidate
1. Bring PR #11 onto current main and resolve the conflict.
2. Make `ts-sdk/src/token.ts` mint/verify `v2.` (ACTENON-JCS-STRICT-1) and keep `v1.` acceptance. Fix the ESM import
   specifiers (`./protocol` → `./protocol.js`).
3. Add cross-language token vectors (ascii, non-ascii, decimal) that Python and TS must both verify.
4. Re-enable Permit CI and make it a required check.
