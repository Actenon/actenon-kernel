# AIRLOCK-001 acceptance criteria (FROZEN)

Frozen on 2026-10-03, before any Airlock implementation. These criteria and their measurement methods
are not changed after results are observed. A criterion that cannot be met is reported as FAIL with its
evidence, never redefined. Only when A1–A15 are all PASS may the result be stated as
`AIRLOCK V1 NORTH STAR: PASS`.

## Goal
A previously unseen real agent can be protected by Airlock with minimal effort, automatically generated
authority, understandable diffs and real runtime blocking:

```
A normal developer can install Airlock, point it at a real AI agent they did not write,
automatically discover the agent's consequential authority, run that agent normally,
see exactly when code changes introduce new powers, and have unapproved powers blocked at runtime.
```

## Definitions
- **Consequential capability**: an operation with an external side effect: an HTTP request other than
  GET/HEAD/OPTIONS, any HTTP request carrying a credential Airlock holds, a write/delete of a file outside
  the agent's own temporary space, process execution.
- **Authority entry**: `(action, resource)`, e.g. `(github.issue.create, github.com/acme/support)`,
  `(http.post, api.openai.com/v1/chat/completions)`, `(filesystem.write, ./reports/)`.
- **Resolved**: the resource is a literal in the source, or a value taken from the project's own
  configuration at `airlock init` time (recorded with its provenance). Anything else is **unresolved**.
- **Supported consequential path** (v1): outbound HTTP/HTTPS from the agent process tree (enforced by the
  Airlock edge proxy); for Python agents also file writes, file deletes, process execution and direct
  socket connections (enforced by an interpreter audit hook installed by `airlock run`).
- **External agent**: an open-source AI-agent or tool-using project not written by Actenon, used at a
  recorded upstream commit, with no application-logic change made to suit Airlock.
- **Stand-in upstream**: a local recording server answering for a real host (e.g. `api.github.com`,
  `api.openai.com`) when the evaluation has no credentials for that service. It is reached only through
  Airlock's normal edge, which makes every authority decision on the real hostname and path; it records
  every request it receives, including headers. A scripted LLM stand-in replays a fixed sequence of
  model responses (including tool calls). Stand-ins are allowed only for services needing credentials
  the evaluation lacks, are disclosed in every result they touch, and at least one case study must also
  exercise a real public endpoint through the edge.

## Criteria and measurement

| # | Criterion | PASS requires (measurement) |
|---|---|---|
| A1 | One product install | In a fresh environment with no Actenon source importable, one command (`pipx install actenon-airlock` or equivalent) installs Airlock and every internal component; `airlock --version` reports Airlock and the bundled component versions; no separate protocol/kernel/Permit/SDK install or configuration. |
| A2 | ≤ 5-minute real-agent onboarding | For each of ≥ 3 external agents, with prerequisites installed (Python, the agent's own dependencies per its README, Airlock): wall-clock from entering the fresh clone to the end of `airlock init` plus a first successful legitimate `airlock run` is ≤ 300 s, timed by script. Every manual step and workaround is recorded. |
| A3 | Automatic authority discovery | The authority used at runtime is produced by `airlock init`. No hand-written policy file. Human input is allowed only as a bounded decision for authority Airlock reports as unresolved (exact target / deny / intentionally dynamic), never as policy authoring. |
| A4 | Action + resource authority | Every manifest entry whose resource is resolvable (definition above) carries that exact resource. Audited per case study against the source: a broad action without its knowable resource is a FAIL. |
| A5 | Fail closed | Automated tests show, and no case study contradicts: unresolved target never becomes `*` or any wildcard; a capability absent from the approved manifest is denied; an empty manifest denies every consequential action; an unknown host or route is denied; an unverified or mismatched proof never reaches the upstream. Generated manifests contain no wildcard resource. |
| A6 | Normal agent behaviour works | In each case study a legitimate task completes under `airlock run` with the agent's normal exit status and its expected effect observed (upstream received the expected allowed requests, or the expected file exists). |
| A7 | Unapproved new power blocked | In each case study a code change (recorded diff) adds one consequential capability; when triggered under `airlock run` it is refused, the upstream records zero requests for it, and the agent sees a refusal. |
| A8 | Authority diff | `airlock diff` reports added and removed authority between the approved manifest and the current code: machine-readable JSON, a concise terminal view, and a GitHub markdown view. Expansion (NEW POWER, needs approval) is distinguishable from reduction (REMOVED POWER). Covered by tests and shown in each case study. |
| A9 | CI / PR mode | A GitHub Action / check runs `airlock check` on a real pull request on GitHub and reports, from the real source diff, the powers the PR adds, with "BLOCKED UNTIL APPROVED" for unapproved expansion (job summary plus annotation). Evidence: the GitHub run URL. |
| A10 | Execution integrity | For every supported consequential path: authorised entry == evaluated action == proof-bound action (kernel PCCB intent: capability, target, parameters) == executed request. Tests with a recording upstream show the forwarded request equals the evaluated one, and that changing any bound field after authorisation is refused. |
| A11 | Credential safety | Real credentials are held by Airlock, never placed in the agent's environment (the agent sees a placeholder). A denied operation never receives a credential: the recording upstream sees no request, and the secret appears in no denial response, receipt or log. Tested and shown in each case study. |
| A12 | Receipts | Every allowed consequential action has a receipt (action, target, authority source, code/source provenance, decision, proof/receipt id, timestamp, execution result); every denial has one (requested action, target, reason, credential released: NO, execution occurred: NO). Human-readable by default; the kernel receipt for an allowed action verifies offline. |
| A13 | Fresh public artefacts | A1 and at least one case study repeated with Airlock and all internal components installed from the public registries only (no local source, no local index). Requires the released ecosystem. |
| A14 | Documented quickstart | The README quickstart's commands run verbatim in a GitHub CI job and pass. |
| A15 | Three external case studies | ≥ 3 external agents with materially different architectures; for each: upstream URL and commit, setup log and timing, manual steps, generated manifest, run log, change diff, `airlock diff` output, block evidence, receipts, all preserved under `airlock/evidence/`. |

Candidate-artefact results (Airlock or components installed from a local index of unreleased builds)
are reported as CANDIDATE and do not satisfy A1 or A13.
