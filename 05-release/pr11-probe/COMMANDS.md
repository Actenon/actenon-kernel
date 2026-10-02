# PR #11 probe (2026-10-02)
- Permit wheel built from `git archive ef20ad7` (PR #11 head) with `uv build --wheel`, installed in a clean py3.12 venv (actenon_permit.__version__ == 2.0.0, file in site-packages).
- TS: `npm i @actenon/sdk@1.4.0` into an empty dir. Driver t.mjs calls `verifyGrantToken(token, key)`.
- Tokens minted by PR #11 `grant_to_token` with ACTENON_SIGNING_KEY=pr11-interop-test-key-0123456789abcdef (tokens.json).
