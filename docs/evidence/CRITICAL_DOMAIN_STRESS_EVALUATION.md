# Actenon Critical-Domain Adversarial Stress Evaluation

## Summary

This document records a real, single-session adversarial evaluation of Actenon against a fresh public clone of the repository.

It is not a fabricated two-week observation. No longitudinal, production, customer, external-audit, or live-deployment claims are made.

The purpose of this evaluation was to answer one narrow question:

> When consequential AI-agent actions are routed through an Actenon-protected boundary, does the boundary refuse unproven, mismatched, expired, replayed, or policy-denied actions before side effects occur, while allowing valid proof-bound actions to execute once?

Under the tested local conditions, the answer was yes.

## Executive Verdict

Held under tested conditions.

Actenon’s core claim held across the tested local proof-bound execution model:

> No valid proof, no execution.

The evaluation produced:

| Evidence | Result |
| --- | ---: |
| Full public-clone test suite | 463 passed, 3 skipped |
| Conformance suite | 33 passed, 0 skipped |
| Release gate | PASS |
| Ruff check | PASS |
| Public boundary validation | PASS |
| Consequential Action Coverage Matrix runs | 10 |
| Representative local scenarios per run | 540 |
| Total representative local scenarios | 5,400 |
| Refusal artifact checks across 10 runs | 4,320 |
| Receipt artifact checks across 10 runs | 1,080 |
| Valid proof-bound execution checks across 10 runs | 1,080 |

The tested boundary refused missing-proof, mismatched-action, parameter-mismatch, audience-mismatch, tenant/subject-mismatch, expired-proof, replay, and policy-denied attempts. Valid proof-bound actions executed once and emitted receipt evidence.

## Method

Repository cloned:

text https://github.com/Actenon/actenon.git 

Evaluation type:

text Real single-session local stress evaluation. Not a two-week observation. Not a live production deployment test. 

Commands executed:

bash bash scripts/demo_hero.sh python3 -m actenon.cli conformance run python3 -m pytest tests/ -q bash scripts/verify_release_gate.sh python3 -m actenon.cli coverage run 

The coverage matrix was run ten times.

The evaluation used the local Actenon development proof mode. The local HMAC signer is intentionally marked as development/demo-only and is not represented as production signing custody.

## Public Clone Test Results

Full test suite:

text 463 passed, 3 skipped, 279 warnings in 32.33s 

Conformance suite:

text Conformance version: 1.0.0 Conformance tests passed. Ran 33 test(s). Skipped: 0. Mark eligibility: Actenon Verified (Conformance 1.0.0) 

Release gate:

text PASS: Release gate completed. Coverage matrix, keystone, full suite, ruff, public boundary, and archive checks are green. 

Ruff:

text All checks passed! 

Public boundary validation:

text Tracked private Cloud/GTM material: none Tracked local runtime/archive material present in working tree: none PASS: git-tracked public boundary check PASS: package build excludes private/local material PASS: public release archive excludes private/local/generated material 

## Critical Domains Tested

The coverage matrix exercised representative consequential action surfaces across nine high-impact domains.

| Domain | Why it matters |
| --- | --- |
| DevOps | Agent mistakes can delete production databases, change infrastructure, disable monitoring, or deploy unsafe code. |
| Fintech | Agent mistakes can duplicate payments, redirect payouts, approve fraudulent invoices, or release settlements incorrectly. |
| IAM / Access Control | Agent mistakes can grant admin rights, disable MFA, rotate keys, or create privileged service accounts. |
| Database | Agent mistakes can delete rows, mutate balances, change tenant ownership, or remove audit records. |
| Browser / Computer Use | Browser agents can submit forms, approve workflows, change settings, or trigger external side effects. |
| MCP Tools | MCP tools expose direct action surfaces where agent intent can become real system mutation. |
| Data Export | Agent mistakes can exfiltrate customer data, regulated records, files, reports, or tenant-crossing data. |
| Email / Communications | Agent mistakes can send customer emails, legal notices, status updates, or notification blasts. |
| Code Agent Operations | Coding agents can edit files, delete repositories, open pull requests, change build scripts, or modify deploy paths. |

## Critical-Domain Coverage Matrix

Each coverage run reported:

text Total scenarios: 540 Domains covered: 9 

Ten runs produced:

text Total representative local scenarios: 5,400 

Domain evidence per run:

text - DevOps:                   60 checks - Fintech:                  60 checks - IAM / Access Control:     60 checks - Database:                 60 checks - Browser / Computer Use:   60 checks - MCP Tools:                60 checks - Data Export:              60 checks - Email / Communications:   60 checks - Code Agent Operations:    60 checks 

Proof-bound execution checks per run:

text - Missing proof refused:                     54/54 - Action hash mismatch refused:              54/54 - Parameter mismatch refused:                54/54 - Audience mismatch refused:                 54/54 - Tenant / subject mismatch refused:         54/54 - Expired proof refused:                     54/54 - Replay attempts refused:                   54/54 - Policy-denied actions refused:             54/54 - Valid proof-bound actions executed once:  108/108 

Artifact evidence per run:

text - Refusal artifacts emitted:  432/432 - Receipt artifacts emitted:  108/108 

Across ten runs:

| Evidence type | Count |
| --- | ---: |
| Total representative scenarios | 5,400 |
| Missing-proof refusals checked | 540 |
| Action-hash mismatch refusals checked | 540 |
| Parameter-mismatch refusals checked | 540 |
| Audience-mismatch refusals checked | 540 |
| Tenant / subject mismatch refusals checked | 540 |
| Expired-proof refusals checked | 540 |
| Replay refusals checked | 540 |
| Policy-denied refusals checked | 540 |
| Valid proof-bound executions checked | 1,080 |
| Refusal artifact checks | 4,320 |
| Receipt artifact checks | 1,080 |

## Adversarial Classes Tested

| Adversarial class | Expected result | Observed result |
| --- | --- | --- |
| Missing proof | Refused before side effect | Refused |
| Wrong action hash | Refused before side effect | Refused |
| Parameter mismatch | Refused before side effect | Refused |
| Audience mismatch | Refused before side effect | Refused |
| Tenant / subject mismatch | Refused before side effect | Refused |
| Expired proof | Refused before side effect | Refused |
| Replay of valid proof | Refused before second execution | Refused |
| Policy-denied action | Refused before side effect | Refused |
| Valid exact proof | Executed once | Executed once |
| Receipt artifact emission | Receipt emitted for allowed action | Emitted |
| Refusal artifact emission | Refusal emitted for denied action | Emitted |

## Hero Demo Evidence

The hero demo showed the core execution-boundary contrast:

text Agent attempts:   database.delete_table production_customers  WITHOUT proof gate:   WOULD EXECUTE   side_effect_executed: true   consequence: destructive action reaches side effect path  WITH ACTENON:   REFUSED   reason_code: ACTION_HASH_MISMATCH   side_effect_executed: false  VALID PROOF:   EXECUTED ONCE   side_effect_executed: true 

Representative artifact digests from the run:

text refusal artifact_digest: sha256:3abb626c790fd71305a97e0056ff7797ddd5ff4d27e1f294158f9fe252dcbaa6 receipt artifact_digest: sha256:80896edb20bac4da429b3c8a25f2383ef088f6130e9ca5e1441d1ed7fc86abb6 

## Domain Findings

### DevOps

DevOps actions are high consequence because an agent can delete production databases, terminate compute, change firewall rules, disable monitoring, rotate secrets, delete backups, or trigger a deployment.

The matrix tested representative DevOps-style consequential action patterns and verified that actions without exact proof were refused. Valid proof-bound actions executed once. Replay attempts were refused.

The tested result supports the claim that when DevOps actions are routed through a protected Actenon boundary, proof becomes a precondition for execution.

### Fintech

Fintech actions are high consequence because wrong side effects can move money, duplicate payments, redirect payouts, approve fraudulent invoices, release refunds, or mutate settlement state.

The matrix tested representative financial side-effect classes and verified refusal for missing, mismatched, expired, replayed, and policy-denied proofs. Valid exact-proof executions produced receipt evidence.

This supports Actenon’s relevance to payment, refund, invoice, and settlement-style execution boundaries, subject to production integration and external review.

### IAM / Access Control

IAM actions are high consequence because an agent can grant admin rights, disable MFA, create service accounts, rotate keys, add users to privileged groups, or alter access policies.

The matrix tested representative IAM and access-control action classes and verified that unproven or mismatched requests were refused before execution.

This supports the use of Actenon as an execution-edge control around privileged access mutation paths, while not replacing IAM itself.

### Database

Database actions are high consequence because an agent can delete records, mutate balances, change ownership, remove audit trails, alter entitlements, or cross tenant boundaries.

The hero demo specifically exercised a production-database deletion-style action. Without a proof gate, the side-effect path would be reached. With Actenon, the action was refused with ACTION_HASH_MISMATCH.

This directly demonstrates the “wrong exact action” failure mode Actenon is designed to block.

### Browser / Computer Use

Browser and computer-use agents are high consequence because form submissions, approval clicks, console actions, and administrative UI changes can create real business side effects.

The matrix tested browser/computer-use style actions as consequential action surfaces. The protected boundary refused unproven or mismatched attempts and allowed valid proof-bound actions once.

This supports Actenon’s role as a control for browser-agent and computer-use execution paths, provided the final side effect is routed through a protected endpoint.

### MCP Tools

MCP tools are high consequence because they expose callable tool surfaces where model intent can become a real mutation in a database, file system, API, or provider.

The matrix and repository tests exercised MCP protected-tool paths. Missing and invalid proof paths were refused, and valid proof-bound paths produced receipt evidence.

This supports Actenon’s use as a proof gate for consequential MCP tools.

### Data Export

Data export actions are high consequence because an agent can expose customer data, regulated records, tenant data, files, or internal reports.

The matrix tested data-export style actions and verified refusal for unproven and mismatched requests.

This supports Actenon’s relevance to export/transmit boundaries, while not claiming to replace output-side DLP.

### Email / Communications

Communications actions are high consequence because an agent can send customer emails, legal communications, status updates, internal announcements, or notification blasts.

The matrix tested email/communications-style side effects and verified proof-bound refusal and execution behavior.

This supports the use of Actenon for send/notify/post boundaries where a protected endpoint controls the actual side effect.

### Code Agent Operations

Code-agent actions are high consequence because coding agents can edit files, change build scripts, open pull requests, alter deploy paths, remove tests, or create destructive automation.

The matrix tested representative code-agent operation surfaces and verified refusal for unproven or mismatched actions.

This supports Actenon’s relevance to coding-agent execution boundaries, especially where code changes can reach CI/CD or production systems.

## Artifact Evidence

The evaluation produced structured evidence in the form of Receipt and Refusal artifacts.

Per coverage run:

text Refusal artifacts emitted: 432/432 Receipt artifacts emitted: 108/108 

Across ten runs:

text Refusal artifact checks: 4,320 Receipt artifact checks: 1,080 

The hero demo produced artifact paths for both refusal and execution receipt evidence:

text refusal artifact: artifacts/hero_demo_runtime/live/simulations/replit/refusal.json receipt artifact: artifacts/hero_demo_runtime/live/simulations/replay-refused/execution_receipt.json 

The artifacts included digest evidence, outcome, side-effect status, receipt or refusal identifiers, and reason codes.

## Failure Analysis

No Actenon boundary failure was observed in the recorded evaluation.

The full test suite passed:

text 463 passed, 3 skipped 

The release gate passed:

text PASS: Release gate completed. Coverage matrix, keystone, full suite, ruff, public boundary, and archive checks are green. 

The coverage matrix passed:

text Result: PASS 

One setup issue occurred during the first attempt to run the evaluation script: pytest was not installed in the temporary virtual environment. This was an environment preparation issue, not an Actenon runtime failure. After installing pytest, ruff, and build, the evaluation completed successfully.

Recommended improvement: the reproducibility script should either install the required developer test dependencies or clearly state them before running the full suite and release gate.

## Security Boundaries and Honest Limits

This evaluation supports the narrow tested claim:

> If a consequential action is routed through an Actenon-protected endpoint, the tested local proof gate refused missing, mismatched, expired, replayed, tenant/subject/audience-mismatched, and policy-denied attempts, while allowing valid proof-bound actions to execute once.

This evaluation does not prove:

- live production provider finality
- protection for actions that bypass the protected endpoint
- protection where an agent still holds raw production credentials and can use a side-door path
- that a bad-but-valid authorized action is good
- replacement of IAM, OAuth, service mesh, API gateways, approvals, monitoring, or DLP
- prevention of in-band model data disclosure
- regulator endorsement
- insurer endorsement
- external audit approval
- long-running production stability

The stress battery is local and representative. It is not a live production deployment test.

## Adoption Readiness

### CISO

A CISO would understand the value because Actenon gives a deterministic execution boundary and structured refusal/receipt evidence.

They would likely trust the repo enough to test because the public clone passes the suite, conformance, release gate, public-boundary validation, and coverage matrix.

Adoption blockers: external audit, production deployment examples, key custody guidance, integration patterns with IAM/SIEM/GRC, and proof of operational use.

### Platform Engineering Lead

A platform lead would understand the value as an enforcement layer at the endpoint or gateway.

They would likely test it because the quickstart, protected endpoint model, MCP examples, and coverage matrix are concrete.

Adoption blockers: production-grade deployment templates, latency benchmarks, service-mesh/API-gateway examples, and operational runbooks.

### AI Agent Framework Maintainer

A framework maintainer would understand the value because Actenon does not require the model to be trusted and can protect tool execution surfaces.

They would likely test it for MCP/tool-calling flows.

Adoption blockers: minimal adapter examples across popular frameworks, stable SDK ergonomics, and compatibility guarantees.

### Regulated Fintech Operator

A fintech operator would understand the value for payments, refunds, settlements, invoice approval, and financial mutation paths.

They would not adopt directly from this evidence alone, but it is credible enough for controlled production-security evaluation.

Adoption blockers: external audit, formal threat model review, KMS/HSM deployment, segregation-of-duty workflows, reconciliation, and compliance mapping.

### Healthcare Technology Operator

A healthcare operator would understand the value for patient-record mutation, PHI export, clinical task reassignment, and scheduling actions.

They would require deeper review before adoption.

Adoption blockers: privacy controls, EHR-specific integration, HIPAA/NHS DSPT-style evidence, audit retention, and clinical safety governance.

### Skeptical Open-Source Maintainer

A skeptical maintainer would value that scanner language avoids vulnerability theatre and that the project is explicit about limits.

They would likely appreciate the local reproducibility and refusal/receipt artifacts.

Adoption blockers: avoiding overclaiming, keeping the README concise, maintaining green CI, and demonstrating real integrations.

## Final Recommendation

Based on this evaluation, Actenon is:

- ready to star and test
- ready for design-partner evaluation
- ready for production-security evaluation in controlled environments

It is not yet externally audited production infrastructure, and should not be represented as such.

The strongest supported conclusion from this run is:

> Actenon’s local proof-bound execution boundary held across 5,400 representative critical-domain scenarios, refused unproven and mismatched consequential actions, blocked replay, allowed valid exact-proof actions once, and produced structured Receipt and Refusal evidence under the tested conditions.
