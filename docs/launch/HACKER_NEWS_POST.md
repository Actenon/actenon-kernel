# Hacker News Launch Post

Use this as a starting draft. Replace `REPO_URL` and the hero GIF placeholder before posting.

## Show HN Draft

Title:

```text
Show HN: Actenon - proof gates and receipts for consequential AI actions
```

Post:

```markdown
Hi HN,

I built Actenon, an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

Core idea:

> Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

Most AI safety tooling focuses on prompts, evals, policy text, or post-hoc logs. Actenon focuses on the execution boundary: the moment an agent-selected action is about to mutate a database, delete a file, grant access, release money, send a message, run a tool, or trigger a workflow.

The rule is simple:

> No valid proof, no execution. Every consequential AI action leaves a verifiable receipt.

Demo GIF:
![Actenon demo: unproven agent action refused before side effect](docs/assets/actenon-hero-demo.gif)

Local demo:

```bash
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh
```

The demo is local-only. It simulates an agent trying a consequential action, shows the unprotected "would execute" path, then shows Actenon refusing the same action without matching proof and writing a Refusal artifact. It also shows the valid-proof path emitting a Receipt.

There is also a local scanner:

```bash
actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool
```

The scanner maps candidate agent-controlled action surfaces. It does not accuse a repo of being vulnerable. It is meant to help maintainers find places where proof gates, approval/evidence policy, credential brokering, replay protection, and Receipt/Refusal logging may be useful.

What Actenon is:
- an execution-boundary proof gate
- a Receipt/Refusal artifact format
- local verification and conformance tests
- a way to remove standing production credentials from agent runtimes when deployed behind protected endpoints

What Actenon is not:
- not a hallucination detector
- not an identity provider
- not a claim that scanner findings are vulnerabilities
- not proof of downstream business correctness
- not a hosted production signing-custody claim in the open kernel

Repo: REPO_URL

I would love technical feedback, especially from people building MCP servers, browser/computer-use agents, coding agents, workflow tools, or protected API endpoints. The design question I care about most is where the proof boundary should sit so agent systems stay usable without letting model-selected tool calls directly hold production authority.
```

## Short Comment Follow-Up

Use this if someone asks how this differs from guardrails:

```markdown
The intended distinction is that guardrails mostly try to influence or judge the model before it acts. Actenon sits at the execution boundary. The protected endpoint verifies a signed proof bound to the exact action parameters, refuses mismatches before the side effect, brokers credentials only after verification, and emits a Receipt or Refusal artifact.

It does not stop the model from trying. It only helps stop the action from executing when the action is routed through a protected boundary.
```

## Safe Claim Checklist

- Keep `REPO_URL` honest.
- Do not add broad safety, formal-audit, approval, or endorsement claims.
- Do not claim the scanner found vulnerabilities in named projects.
- Do not claim hosted production signing custody unless the deployed product actually uses it.
