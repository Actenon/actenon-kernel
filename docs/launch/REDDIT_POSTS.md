# Reddit Launch Posts

Use these as starting drafts. Adapt the title, repo URL, and hero GIF link per community. Keep the tone concrete and avoid drive-by promotion.

## Common Assets

Hero GIF placeholder:

```markdown
![Actenon demo: unproven agent action refused before side effect](docs/assets/actenon-hero-demo.gif)
```

One-command local demo from a clean clone:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

Scanner CTA:

```bash
actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool
```

Core line:

```text
Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.
```

## r/devops

Title:

```text
Open-source proof gate for AI agents before they touch infra or workflows
```

Post:

```markdown
I have been working on Actenon, an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

The DevOps version of the problem is simple: if an agent can trigger deploys, run shell commands, mutate config, call cloud APIs, or operate MCP tools, the interesting boundary is not only "did the model say the right thing?" It is "can this action execute without a proof-bound approval?"

Actenon sits at that execution boundary:
- no valid proof, no execution
- exact action parameters are bound into the proof
- credentials can be brokered only after verification
- allowed and refused actions emit Receipt/Refusal artifacts

Local demo:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

There is also a local scanner that maps candidate agent-controlled action surfaces:

```bash
actenon scan repo --path .
```

The scanner is advisory. It does not claim your repo is vulnerable and it does not prove runtime reachability. The goal is to help maintainers find tool handlers, workflow runners, shell/API paths, and credential boundaries that deserve proof, approval, replay/idempotency, and audit controls.

Repo: REPO_URL
Hero demo: docs/assets/actenon-hero-demo.gif

I would appreciate feedback from people operating agentic DevOps tools or MCP servers. In particular: where would you put the proof boundary so it is enforceable without making the system unusable?
```

## r/netsec

Title:

```text
Actenon: static authority map plus proof-bound execution gate for AI agents
```

Post:

```markdown
I built Actenon, an Apache-2.0 open kernel for proof-bound execution of consequential AI agent actions.

The threat model is not "the model might produce bad text." It is "a model-selected tool call may reach a side effect with standing credentials and no proof gate in between."

Core message:

> Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

Actenon has two adoption surfaces:

1. A protected execution path: verify proof bound to the exact action, consume replay/escrow where configured, broker credentials after verification, execute or refuse, emit Receipt/Refusal.
2. A local scanner: map candidate agent-controlled action surfaces and missing visible controls.

Local demo:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

Scanner:

```bash
actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool
```

Limitations, explicitly:
- scanner findings are static advisory findings, not vulnerability claims
- runtime reachability and exploitability are not proven by the scanner
- Actenon only protects paths routed through a protected endpoint or equivalent enforcement boundary
- it does not make a bad-but-authorized action good
- the open kernel does not claim hosted production signing custody

Repo: REPO_URL
Hero demo: docs/assets/actenon-hero-demo.gif

I would value review of the trust-boundary model, receipt shape, scanner language, and what additional adversarial tests you would want before broad adoption.
```

## r/LocalLLaMA

Title:

```text
Local proof gate demo for agents that can actually do things
```

Post:

```markdown
I built Actenon, an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

As local agents get better at browsing, coding, using tools, and operating desktops, the question becomes: what can the agent actually do, and is there a proof gate before the side effect?

Actenon is not a model benchmark or a prompt guardrail. It sits at the execution boundary:

- the agent can request an action
- the protected endpoint verifies proof for the exact action
- no valid proof means no execution
- allowed/refused decisions write verifiable Receipt/Refusal artifacts

Run the local demo:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

Try the local scanner:

```bash
actenon scan repo --path .
```

The scanner maps agent authority. It does not accuse a repo of being vulnerable. It is a practical way to find browser actions, tool handlers, MCP tools, shell paths, API calls, workflow runners, or credential-backed paths that might need a proof or approval boundary before autonomous execution.

Repo: REPO_URL
Hero demo: docs/assets/actenon-hero-demo.gif

I am especially interested in feedback from people building local browser/computer-use agents and tool registries.
```

## MCP / Agent Community Post

Title:

```text
MCP tools are where agent decisions meet real actions. I built a proof gate for that boundary.
```

Post:

```markdown
MCP makes tool execution wonderfully composable. It also makes the execution boundary very explicit: a model selects a tool, the tool handler runs, and sometimes the world changes.

I built Actenon, an Apache-2.0 proof gate and receipt standard for that boundary.

Core line:

> Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

For MCP/tool systems, the intended path is:

```text
agent -> MCP tool call -> Actenon proof gate -> tool executes or refuses -> Receipt/Refusal
```

Local demo:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

MCP quickstart:

```bash
python3 -m examples.mcp_protected_tool.demo --scenario missing-proof
python3 -m examples.mcp_protected_tool.demo --scenario allow
```

Scanner:

```bash
actenon scan mcp --path examples/mcp_server_protected_tool
```

The scanner is advisory and private by default. It maps candidate consequential action surfaces and recommends controls; it does not publish grades or claim vulnerabilities.

Repo: REPO_URL
Hero demo: docs/assets/actenon-hero-demo.gif

I would love feedback from MCP server maintainers on the smallest wrapper shape that feels natural around consequential tool handlers.
```
