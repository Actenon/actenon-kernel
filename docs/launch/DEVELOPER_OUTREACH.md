# Developer Outreach

Use these notes for direct, respectful outreach. Do not imply that a maintainer's project is vulnerable. Offer private, advisory review and make it clear that Actenon Scanner maps candidate authority surfaces rather than proving exploitability.

## Agent Framework Maintainers

Subject:

```text
Private feedback request: proof-bound execution gates for agent actions
```

Message:

```text
Hi <name>,

I am building Actenon, an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

The core idea is:

Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

Actenon sits at the execution boundary: verify a proof bound to exact action parameters, refuse mismatches before side effects happen, broker credentials only after verification, and emit Receipt/Refusal artifacts.

I am reaching out because agent frameworks define the tool/action boundary developers build on. I would value your feedback on whether Actenon's protected-execution shape would feel natural around your tool handlers or action registries.

Local demo:
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

Scanner:
actenon scan repo --path .

The scanner is private and advisory. It maps candidate action surfaces and missing visible controls; it does not claim vulnerabilities or publish grades.

Repo: REPO_URL
Hero demo placeholder: docs/assets/actenon-hero-demo.gif

If useful, I would be happy to run a private scanner pass and share only maintainers-first integration notes.
```

## MCP Server Maintainers

Subject:

```text
MCP tool proof gate feedback request
```

Message:

```text
Hi <name>,

I am working on Actenon, an Apache-2.0 proof gate and receipt standard for consequential AI agent actions.

MCP tools are a natural boundary: a model selects a tool, the tool handler runs, and sometimes the world changes.

Actenon's intended MCP path is:

agent -> MCP tool call -> proof gate -> tool executes or refuses -> Receipt/Refusal

The local MCP quickstart shows a simulated consequential tool that refuses without proof and emits a receipt when valid proof is present:

python3 -m examples.mcp_protected_tool.demo --scenario missing-proof
python3 -m examples.mcp_protected_tool.demo --scenario allow

The broader local demo is:

python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

There is also an advisory scanner:

actenon scan mcp --path <your-mcp-server>

The scanner maps candidate MCP tool side effects and missing visible controls. It is not a vulnerability accusation, does not prove runtime exploitability, and does not publish grades.

Repo: REPO_URL
MCP quickstart: docs/integrations/MCP_QUICKSTART.md

I would value feedback on the wrapper shape and what would make protected MCP tool adoption feel lightweight.
```

## Security Engineers

Subject:

```text
Review request: execution-boundary proof for AI agents
```

Message:

```text
Hi <name>,

I am building Actenon, an Apache-2.0 open kernel for proof-bound execution of consequential AI agent actions.

The security model is intentionally narrow:

Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

Actenon does not try to prove the model is aligned. It focuses on the execution boundary:

- proof bound to exact action parameters
- audience/action/scope/time binding
- replay or escrow consumption where configured
- credentials brokered after verification
- Receipt/Refusal artifacts for allowed and blocked decisions

Local demo:
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

Scanner:
actenon scan repo --path .

The scanner output is deliberately worded as a consequence-class map, not a vulnerability severity report. Runtime reachability, exploitability, production exposure, and business impact are not proven by a static scan.

Repo: REPO_URL
Threat model: THREAT_MODEL.md
Security testing: SECURITY_TESTING.md

I would appreciate feedback on the trust-boundary model, adversarial test coverage, scanner wording, and any gaps you would want closed before considering this for agent systems near real operations.
```

## Short Maintainer DM

```text
I am building Actenon, an Apache-2.0 proof gate and receipt standard for consequential AI agent actions.

Core line: prompt injection can make an agent want to act; it should not be able to make the action execute without proof.

If you are open to it, I would love to run the local scanner privately against your agent/tool surface and share advisory integration notes only. No public grades, no vulnerability claims.

Repo: REPO_URL
Demo: python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```
