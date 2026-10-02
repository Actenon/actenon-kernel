# Permit next-version determination: PR #11 vs the "1.5.0" plan (2026-10-02)

Status: **determined from the compatibility contract and an executed probe.** The release decision belongs to the owner.

## The contract Permit actually states
1. `SPEC.md` §9 (Versioning, main `c1eea9c`): the grant format "MUST NOT change the meaning of existing fields" and "MUST NOT … change the
   canonical-JSON rule", and "A future `version` field will be added when the format diverges non-additively."
2. `ARCHITECTURE.md` §6.3: "SemVer + dual-support windows on the canonicalization/PCCB/receipt contracts."
3. PyPI classifier "Development Status :: 4 - Beta" with version ≥ 1.0.0. SemVer applies from 1.0.0. Permit has **no** documented
   security-fix exception comparable to kernel `VERSIONING.md` §1.4.

## What PR #11 (`ef20ad7`, base `ed0a68e`) changes, as measured
Probe: PR #11 wheel built from `git archive ef20ad7` into a clean venv; npm `@actenon/sdk@1.4.0` installed into an empty dir.
Raw output: `pr11-probe/RESULTS.txt`.

| change | observed | old consumer impact | class |
|---|---|---|---|
| `grant_to_token` mints `v2.` tokens | both minted tokens are `v2.…` | `@actenon/sdk@1.4.0` `verifyGrantToken` → **REJECTED "unsupported token version (expected 'v1.')"** for ASCII and non-ASCII grants | **breaking** (wire; a new producer is unreadable by the published consumer) |
| public `canonical_json` delegates to ACTENON-JCS-STRICT-1 | `canonical_json({"a":1.5})` → **raises `CanonicalisationError`** (1.4.0 returned a string) | callers passing floats now crash | **breaking** (public API behaviour) |
| canonical-JSON rule for grants changed | per CHANGELOG; signatures differ for non-ASCII and Decimal | violates `SPEC.md` §9 unless versioned. PR #11 versions it via the `v2.` prefix and `chain_version` | breaking, but explicitly versioned |
| ledger `chain_version` | per diff: legacy rows verified with the legacy canonicaliser | older Permit reading a new ledger would mis-verify new rows | breaking for downgrade only |
| `token_to_grant` still accepts `v1.` | per diff | none | additive |

Control (`pr11-probe/RESULTS.txt`, CONTROL section): released Permit **1.4.0** `v1.` tokens verify in `@actenon/sdk@1.4.0` for an ASCII
`agent_id` but are **REJECTED (signature mismatch) for a non-ASCII `agent_id`**. The cross-language defect PR #11 targets is real
in the released versions. It fails closed (TS refuses valid grants), so it isn't an authorisation bypass.

## Determination
- **PR #11 as written is a MAJOR change. 2.0.0 is the correct number. "1.5.0" would silently downgrade a breaking change** to a
  minor and is rejected on the evidence above.
- **PR #11 is not releasable as written, even as 2.0.0.** (a) It doesn't update `ts-sdk/src/token.ts`, so the 2.0.0 Python broker would
  mint tokens that the TS SDK of the same release can't read, which breaks Permit's own two-language contract. (b) It is based on
  `ed0a68e`, 11 commits behind main, and conflicts with the programme branch (`src/actenon_permit/__init__.py`). (c) Permit's CI is
  `disabled_inactivity`, so PR #11 has never been gated by CI on GitHub.
- A 1.5.0 is possible **only for a different change**: keep minting `v1.`, add `v2.` acceptance plus opt-in `v2.` minting, and leave
  `canonical_json`'s float behaviour unchanged (a new strict function alongside). That would leave the non-ASCII defect in place for
  default-minted grants, so it isn't equivalent to PR #11.
- Whether Permit's next release is MAJOR doesn't depend on PR #11 alone. The secure-defaults work (`../02-g3/G3-DESIGN.md`) may itself
  remove silent fallbacks to a public dev key, which is a behaviour change for unconfigured deployments; it is classified there.

## Smallest path to a correct Permit 2.0.0 candidate
1. Rebase or merge PR #11 onto the candidate branch and resolve the `__init__.py` conflict (keep the dist-metadata `__version__`).
2. Teach `ts-sdk/src/token.ts` to decode and verify `v2.` (ACTENON-JCS-STRICT-1 canonical bytes, matching `@actenon/protocol`'s
   canonicaliser or a vendored, vector-locked copy) and keep `v1.` acceptance. Add cross-language token vectors (ASCII, non-ASCII,
   Decimal) that both languages must verify.
3. Re-enable Permit CI, so the change is gated at all.
