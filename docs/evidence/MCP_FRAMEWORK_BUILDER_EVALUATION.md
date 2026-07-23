# Actenon MCP Framework Builder Evaluation

## Summary

This document records a real, single-session evaluation of Actenon from the perspective of an MCP framework builder assessing whether Actenon provides a credible proof-gating pattern for consequential MCP tool calls.

It is not a fabricated longitudinal observation. No production deployment, ecosystem adoption, external audit, or live customer claim is made.

The evaluation cloned the public repository, installed Actenon as a visitor would, ran the MCP-specific integration tests, ran the high-level proof gate API tests, ran conformance, and ran the Consequential Action Coverage Matrix.

## Executive Verdict

Held under tested conditions.

From an MCP framework-builder perspective, Actenon’s core MCP claim held under the tested local conditions:

> A consequential MCP tool can refuse execution unless the protected tool boundary receives valid proof bound to the exact action.

The MCP-specific evidence was:

| Evidence | Result |
| --- | ---: |
| MCP integration tests | 7 passed |
| High-level proof gate API tests | 6 passed |
| Conformance suite | 33 passed, 0 skipped |
| Coverage matrix | PASS |
| Representative coverage scenarios | 540 |
| MCP domain checks in coverage matrix | 60 |
| Refusal artifact checks | 432/432 |
| Receipt artifact checks | 108/108 |
| Replay checks | 54/54 refused |
| Valid proof-bound execution checks | 108/108 executed once |

The tested MCP paths refused missing or invalid proof before the tool side effect, produced structured refusal evidence, allowed valid proof-bound execution, and blocked replay.

## Method

Repository cloned:

text https://github.com/Actenon/Actenon.git 

Commit tested:

text e17b4f92df9944868c10fc65adf4951618c816c0 

Python runtime:

text Python 3.9.6 

Evaluation type:

text Real single-session local evaluation. Not a longitudinal observation. Not a live production deployment test. 

Commands run:

bash python3 -m pip install -e ".[asymmetric]" bash scripts/demo_hero.sh python3 -m actenon.cli conformance run python3 -m pytest tests/integration/test_mcp_hero_path.py tests/integration/test_mcp_protected_tool_quickstart.py -q python3 -m pytest tests/integration/test_high_level_gate_api.py -q python3 -m actenon.cli coverage run 

The local Actenon HMAC signer was used only in development/demo mode. The warnings correctly state that production use requires asymmetric, KMS, or HSM signing custody.

## MCP-Specific Test Evidence

The MCP integration tests passed:

text 7 passed, 4 warnings in 0.15s 

The tested MCP paths included:

- missing proof refusal
- refused receipt emission
- preflight refusal before brokered execution
- supported consequential tool execution after proof gate
- MCP protected-tool quickstart behavior

The warnings were expected development-mode signer warnings:

text ACTENON LOCAL HMAC SIGNER IS FOR LOCAL/DEV/DEMO ONLY. The default local proof secret is public; production must use asymmetric well-known/KMS/HSM signing custody. 

No MCP-specific test failure was observed.

## High-Level Gate API Evidence

The high-level proof gate API tests passed:

text 6 passed in 0.09s 

This matters because MCP framework builders need a clean integration surface. The high-level gate API suggests Actenon can be integrated without every MCP framework or tool author manually wiring low-level proof-verification logic.

From a framework-builder perspective, this is important: the lower the integration burden, the more realistic adoption becomes.

## Conformance Evidence

The conformance suite passed:

text Conformance version: 1.0.0 Conformance tests passed. Ran 33 test(s). Skipped: 0. Mark eligibility: Actenon Verified (Conformance 1.0.0) 

This supports the claim that Actenon’s proof, receipt, refusal, replay, and verifier behavior is not just an example-specific implementation but is backed by a conformance surface.

## Consequential Action Coverage Evidence

The coverage matrix passed:

text ACTENON CONSEQUENTIAL ACTION COVERAGE MATRIX  Total scenarios: 540 Domains covered: 9 

Domain evidence included:

text - DevOps:                   60 checks - Fintech:                  60 checks - IAM / Access Control:     60 checks - Database:                 60 checks - Browser / Computer Use:   60 checks - MCP Tools:                60 checks - Data Export:              60 checks - Email / Communications:   60 checks - Code Agent Operations:    60 checks 

Proof-bound execution checks included:

text - Missing proof refused:                     54/54 - Action hash mismatch refused:              54/54 - Parameter mismatch refused:                54/54 - Audience mismatch refused:                 54/54 - Tenant / subject mismatch refused:         54/54 - Expired proof refused:                     54/54 - Replay attempts refused:                   54/54 - Policy-denied actions refused:             54/54 - Valid proof-bound actions executed once:  108/108 

Artifact evidence:

text - Refusal artifacts emitted:  432/432 - Receipt artifacts emitted:  108/108 

Result:

text PASS  No valid proof, no execution. 

## Evaluation as an MCP Framework Builder

### What an MCP framework builder would care about

An MCP framework builder would not primarily care whether Actenon has a dramatic demo. They would care whether it gives MCP servers a reliable, repeatable way to protect consequential tools at execution time.

The critical questions are:

| Question | Observed answer |
| --- | --- |
| Can proof verification happen at the tool execution boundary? | Yes, under tested local MCP paths |
| Can missing proof be refused before side effects? | Yes |
| Can mismatched proof be refused? | Yes |
| Can replay be blocked? | Yes |
| Can valid proof-bound actions execute once? | Yes |
| Are refusal and execution outcomes evidenced? | Yes |
| Is the project honest about local/demo signer limits? | Yes |
| Is the MCP integration ready for production without further work? | Not yet; production templates and key custody guidance are still needed |

## MCP Value Proposition

The strongest MCP-specific value proposition is:

> MCP tools are becoming side-effect surfaces. Actenon gives MCP tool servers a proof gate at the point of execution, so an agent can request an action, but the protected tool refuses unless the exact action has valid proof.

This is materially different from relying on the model, prompt, tool description, or client-side SDK as the trust boundary.

The trust boundary moves to the tool server or protected endpoint.

That matters because an MCP framework cannot assume every model, agent, client, or caller is honest, safe, or under the same operator’s control. A tool server needs a resource-side enforcement point.

## What Actenon Demonstrated for MCP

Under the tested local conditions, Actenon demonstrated:

- missing-proof refusal
- invalid-proof refusal
- action-bound proof enforcement
- replay blocking
- valid proof-bound execution once
- structured receipt evidence
- structured refusal evidence
- high-level gate API coverage
- conformance-backed behavior
- representative MCP-domain coverage inside the broader consequential-action matrix

This supports Actenon as a credible pattern for protecting high-consequence MCP tools.

## What Actenon Does Not Yet Prove for MCP

This evaluation does not prove:

- broad MCP ecosystem adoption
- production readiness across every MCP server framework
- hosted production key custody
- performance under large distributed MCP traffic
- replay-state correctness across horizontally scaled production deployments
- compatibility with every MCP server implementation
- external audit approval
- live provider finality
- protection for tools that bypass the protected endpoint
- protection where an agent still holds raw production credentials and can call the underlying system directly

The tests are local and representative. They are not a substitute for production integration testing.

## Adoption Blockers for MCP Framework Builders

The main blockers are not the core proof-gate behavior. The tested behavior passed.

The blockers are mostly adoption and integration maturity:

1. Dedicated MCP integration guide  
   The repo should have a clear MCP-specific guide that shows missing proof, action mismatch, replay refusal, valid proof execution, and receipt/refusal verification.

2. Framework-neutral adapter documentation  
   MCP builders need to see how Actenon fits native MCP servers, FastMCP-style servers, and future MCP framework abstractions.

3. Proof injection pattern  
   The ideal pattern should keep proof metadata out of the model-facing schema where possible, so the model does not treat proof as ordinary user-controllable input.

4. Shared replay state guidance  
   Production MCP deployments may be horizontally scaled. Replay state needs a clear production pattern.

5. Credential brokering examples  
   The strongest MCP deployment removes standing production credentials from the agent/tool path and brokers short-lived credentials only after proof verification.

6. Production signer guidance  
   The local HMAC signer warnings are good, but MCP adopters will need copy-paste KMS/HSM/asymmetric examples.

7. Minimal examples by tool type  
   MCP builders would benefit from examples for database mutation, file write/delete, external API call, payment/refund, data export, and IAM mutation.

## Recommended Next MCP Work

The next strongest additions would be:

- docs/guides/MCP_PROTECTED_TOOLS.md
- examples/mcp_database_delete_protected/
- examples/mcp_data_export_protected/
- examples/mcp_iam_mutation_protected/
- examples/mcp_payment_refund_protected/
- docs/guides/MCP_REPLAY_STATE_DEPLOYMENT.md
- docs/guides/MCP_CREDENTIAL_BROKERING.md

Each example should show:

- missing proof refused
- proof for safe action reused against harmful action refused
- parameter mismatch refused
- audience mismatch refused
- replay refused
- valid proof executed once
- receipt emitted
- refusal emitted

## Final Recommendation

As an MCP framework builder, I would classify Actenon as:

- Ready to star and test
- Ready for MCP framework maintainers to inspect
- Ready for experimental MCP integrations
- Ready for design-partner evaluation
- Not yet proven as broad production MCP infrastructure

The core tested claim held:

> Actenon can protect consequential MCP tool execution paths by refusing unproven or mismatched actions before side effects, allowing valid proof-bound actions once, blocking replay, and emitting structured Receipt and Refusal evidence.

The strongest honest recommendation is:

> Actenon is credible enough for MCP framework builders to test now. The next adoption leap is not more abstract positioning; it is a dedicated MCP integration guide and a small set of copy-paste protected MCP tool examples showing refusals, replay blocking, valid execution, and evidence artifacts.
