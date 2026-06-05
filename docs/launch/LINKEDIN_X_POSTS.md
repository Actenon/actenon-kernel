# LinkedIn And X Launch Posts

Replace `REPO_URL` and asset placeholders before posting. Keep posts honest: no formal approval claims, no named-project accusations, and no hosted production signing-custody claims unless implemented.

## LinkedIn Long Post

```text
Prompt injection can make an agent want to act.

It should not be able to make the action execute without proof.

Today I am sharing Actenon: an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

The product idea is simple:

No valid proof, no execution. Every consequential AI action leaves a verifiable receipt.

Actenon is built for the boundary where agent decisions meet side effects: MCP tools, browser/computer-use controllers, workflow runners, API connectors, database writes, infrastructure changes, access grants, payments, communications, and other actions that affect real systems.

It is not another prompt guardrail. It sits at the execution boundary:

- verify a proof bound to the exact action parameters
- refuse mismatches before side effects happen
- broker credentials only after verification
- emit Receipt/Refusal artifacts for audit and review

Try the local demo:

python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

Try the scanner:

actenon scan repo --path .

The scanner maps agent authority. It does not accuse a repo of being vulnerable. It gives maintainers a practical map of candidate action surfaces where proof gates, approval/evidence policy, replay protection, credential boundaries, and receipts may be needed.

Apache-2.0. Local-first. No cloud account required for the demo.

Repo: REPO_URL
Hero demo: docs/assets/actenon-hero-demo.gif

Limitations matter: Actenon only protects actions routed through a protected endpoint or equivalent enforcement boundary. It cannot stop a model from trying to act, cannot make a bad-but-authorized action good, and scanner findings are advisory static analysis rather than vulnerability claims.

I would love feedback from agent framework maintainers, MCP server maintainers, security engineers, and teams deploying agents near real operational systems.
```

## X Thread

```text
1/ Prompt injection can make an agent want to act.

It should not be able to make the action execute without proof.

I built Actenon: an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.
```

```text
2/ Core rule:

No valid proof, no execution.
Every consequential AI action leaves a verifiable receipt.

Actenon sits at the execution boundary, where a model/tool decision is about to cause a side effect.
```

```text
3/ Think MCP tools, browser agents, workflow runners, API connectors, database writes, infrastructure changes, access grants, payments, communications, and file mutations.

The question is:

Can the agent act on the world without proof?
```

```text
4/ Local demo:

python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

Hero GIF placeholder:
docs/assets/actenon-hero-demo.gif
```

```text
5/ Scanner CTA:

actenon scan repo --path .
actenon scan mcp --path examples/mcp_server_protected_tool

The scanner maps agent authority. It does not accuse your repo of being vulnerable.
```

```text
6/ Honest limits:

Actenon only protects actions routed through a protected endpoint or equivalent enforcement boundary.

It does not stop a model from trying, prove business correctness, or turn static scanner findings into vulnerability claims.
```

```text
7/ Repo:
REPO_URL

I would love feedback from people building MCP servers, agent frameworks, browser/computer-use agents, coding agents, and security controls for autonomous systems.
```

## Single X Post

```text
Prompt injection can make an agent want to act. It should not be able to make the action execute without proof.

Actenon is an Apache-2.0 open proof gate and receipt standard for consequential AI agent actions.

Local demo:
python3 -m pip install -e ".[asymmetric]" && bash scripts/demo_hero.sh

Scanner:
actenon scan repo --path .

No valid proof, no execution. Every consequential action leaves a verifiable receipt.

Scanner findings are advisory, not vulnerability claims.

REPO_URL
```

## Short LinkedIn Follow-Up

```text
The most useful question for agent security may be:

Where does a model-selected action become a real side effect?

Actenon is my attempt to make that boundary explicit: proof before execution, credentials after approval, Receipt/Refusal after every decision.

If you maintain an MCP server or agent framework and want a private scanner review, I would be glad to help test it quietly and share findings as advisory integration notes, not public grades.
```
