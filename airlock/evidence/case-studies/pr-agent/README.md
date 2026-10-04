# Case study 1: qodo-ai/pr-agent

**Agent:** [qodo-ai/pr-agent](https://github.com/qodo-ai/pr-agent) at `14540faf6ca26256ae3dfcc2f1cd8f57a4c1509d`
(2026-10-03), a pull-request review agent: LiteLLM for the model, PyGithub for GitHub, ~110 Python files.
Not written by Actenon. No application code was changed to suit Airlock.

**Reproduce:** `WORK=/tmp/cs AIRLOCK=$(which airlock) PY=python3 bash run.sh` (writes every file in this directory).

## Setup and onboarding (A2, A3)

| Step | What | Time |
|---|---|---|
| prerequisite (not timed) | `git clone` at the commit above, `pip install -e .` per pr-agent's README; Airlock installed | — |
| 1 | pr-agent's own configuration, per its README: `OPENAI__KEY`, `GITHUB__USER_TOKEN`, `CONFIG__MODEL=gpt-4o` | — |
| 2 | `airlock init --resolve repository=Actenon/actenon-kernel` | 3.1 s |
| 3 | `airlock run -- .venv/bin/pr-agent --pr_url https://github.com/Actenon/actenon-kernel/pull/36 review` | 16.2 s |
| | **total, entering the clone to the end of the first protected run** | **19.3 s** |

No policy was written. The one human input is a bounded decision Airlock asks for because the agent takes its
repository from the PR URL at runtime: *which repository may it act on?* Every GitHub capability discovered in
the code is then authorised on exactly `github.com/Actenon/actenon-kernel` (and, because the code fixes the
name of its optional settings repository but takes the owner at runtime, `github.com/Actenon/pr-agent-settings`).

Discovered and approved (`airlock.json`), each with the code that needs it: `github.repo.read`,
`github.issue.comment`, `github.issue.label`, `github.pull.comment`, `github.pull.review`, `github.pull.update`,
`github.contents.write` on the repository; `github.graphql`; `HTTP POST api.openai.com/v1/chat/completions`
(the model provider, from the configured credential); `http.get api.github.com/notifications` (polling
server); `process.exec git`, `ssh`; a `filesystem.write ./pyproject.toml` from a release script. 41 capabilities
whose target the code decides at runtime (mostly the Bitbucket, Gerrit and local-git providers this run does not
use) stay **blocked**.
Credentials held by Airlock (the agent sees placeholders): `GITHUB__USER_TOKEN`, `OPENAI__KEY`, and the other
provider keys pr-agent reads.

## Normal work (A6)

`2-run.txt`: pr-agent fetched the real PR #36 (2 files, an outside contributor's change), asked the model,
and published its "PR Reviewer Guide" comment and labels: **26 allowed, 0 blocked**. The token was injected
into each authorised GitHub request by the edge (`upstream-github.jsonl`); the agent never had it.

## A new power is blocked (A7, A8, A9, A10, A11)

`3-new-power.diff` makes pr-agent delete the repository after commenting (two lines in
`GithubProvider.publish_comment`).

`4-diff.txt`:
```
NEW POWER DETECTED

+ github.repo.delete
  github.com/Actenon/actenon-kernel
  pr_agent/git_providers/github_provider.py:819 in GithubProvider.publish_comment  (PyGithub Repository.delete)

This authority was not previously approved.
Runtime: BLOCKED until approved (airlock approve)
```
`airlock check` exits 1 (`5-check.txt`). Running the changed agent (`6-run-after-change.txt`):
```
BLOCKED

github.repo.delete
github.com/Actenon/actenon-kernel

Authority not present in approved manifest.

Credential released: NO
Execution occurred: NO
```
The GitHub upstream recorded **0 DELETE requests** (`SUMMARY.json`); the review itself still completed.

## Receipts (A12)

`2-run.receipts.jsonl` / `6-run-after-change.receipts.jsonl`: one per consequential action, with action, target,
authority and its source code location, proof (PCCB) id, kernel receipt id, credential released, execution
occurred, result. `7-blocked-receipts.txt` is the human view. `2-kernel-receipt-verification.txt`:
`actenon-kernel verify-receipt` checks a kernel receipt against its intent and proof offline, PCCB signature
verified.

## What is real and what is a stand-in

Real: pr-agent's code, its dependencies, its CLI, the pull request and every GitHub *read* (relayed to
`api.github.com` without a credential), Airlock's discovery, edge, decisions, proofs and receipts. Stand-ins
(disclosed, `--stand-in`): GitHub *writes* are recorded locally instead of posted on the real PR, and the model
API is a scripted response (`llm-script.json`); this evaluation holds no credentials for either. Every authority
decision is made on the real host and path.

## Defects this case study found in Airlock (all fixed, with tests)

1. Discovery took > 600 s on 113 files (exponential re-evaluation) → memoised: ~3 s.
2. PyGithub objects built by factory methods / assigned in several places were invisible → object kinds join.
3. LiteLLM calls were not mapped → provider endpoint by model; configured-credential endpoints otherwise.
4. Authenticated PyGithub reads had no authority (`github.repo.read`) → the first read was blocked.
5. PyGithub's raw requester (`_requester.requestJsonAndCheck`) and object URLs were invisible → labels/GraphQL.
6. Credential detection swept every upper-case string → only real environment reads, plus provider inference
   for names like `GITHUB__USER_TOKEN`.
7. 27 unresolved items were listed one by one → grouped, one bounded question per group.
8. `uname` (a library's platform probe) was blocked → fixed list of read-only platform probes.
9. A URL whose *repository or workspace* segment was unknown became a template (`api.bitbucket.org/2.0/
   repositories/{}/{}/src`): authority over every repository the token reaches. Templates are now allowed only
   for the final path segment (an item); anything earlier is unresolved and asks for a bounded decision.
