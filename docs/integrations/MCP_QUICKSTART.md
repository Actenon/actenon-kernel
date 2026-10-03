# MCP Quickstart

MCP tools are where agent decisions meet real actions. Actenon belongs at that
tool execution boundary: no valid proof, no side effect, and every allow/refuse
decision leaves a Receipt or Refusal artifact.

This guide is local-only. It does not require Actenon Cloud or a hosted
gateway.

## Connect the server (60 seconds, nothing to install)

Paste this into your MCP client's config (Claude Desktop, ChatGPT, or any
other MCP client):

```json
{
  "mcpServers": {
    "actenon": {
      "command": "uvx",
      "args": ["--from", "actenon-kernel[mcp]", "actenon-mcp", "--demo"]
    }
  }
}
```

In Claude Code, one command registers the same server:

```bash
claude mcp add actenon -- uvx --from 'actenon-kernel[mcp]' actenon-mcp --demo
```

`claude mcp list` then health-checks it and should report `actenon` as
connected. Add `--scope user` before the name to make it available in every
project rather than only the current one. If you write this command by hand,
two details matter:

- **`--from` goes before `actenon-mcp`.** `uvx` treats the first word that is
  not one of its own options as the command to run, and passes everything
  after it to that command. `uvx actenon-kernel --from ...` therefore runs
  the kernel CLI rather than the MCP server, and the client reports the
  connection as closed.
- **Quote `'actenon-kernel[mcp]'`.** zsh (the macOS default shell) treats the
  brackets as a glob and aborts with `no matches found` before the command
  runs.

`uvx` fetches and runs the package on demand, so there is nothing to install
first. Verified from a clean machine — this is the real client handshake, not
a mock-up:

```text
$ launching: uvx --from actenon-kernel[mcp] actenon-mcp --demo

actenon-mcp: DEMO MODE — ephemeral key, not for production.
actenon-mcp: ephemeral in-process key, in-memory replay store, no network calls, no configuration read.
actenon-mcp: proofs minted here verify nowhere else and do not survive a restart.

connected: actenon v1.28.1
protocol : 2025-11-25

tool list received by the client (4 tools):

  * actenon_verify
      required args: ['action_name', 'capability', 'parameters', 'target_type', 'target_id', 'proof']
  * actenon_gate
      required args: ['action_name', 'capability', 'parameters', 'target_type', 'target_id']
  * actenon_receipt
      required args: []
  * actenon_demo_grant
      required args: ['action_name', 'capability', 'parameters', 'target_type', 'target_id']

smoke call — refund with no authority:
  outcome     : REFUSED
  reason_code : PCCB_REQUIRED
  reason      : The protected action did not include a proof credential block.
```

### The tools

| Tool | Question it answers | Side effects |
|---|---|---|
| `actenon_verify` | Would this proof be accepted for this exact action? | None. Pure verification: consumes no replay state, emits no receipt. |
| `actenon_gate` | ALLOW, or a typed refusal? | Enforcement path. Consumes single-use replay state, emits a hash-chained Receipt or Refusal. |
| `actenon_receipt` | What happened, and can I prove the log was not rewritten? | None. Returns the artifact plus its position and hashes in the chain. |
| `actenon_demo_grant` | **Demo only.** Issues a scoped proof. | Absent from a production server — see below. |

Every response carries **both** the machine `reason_code` and a human-readable
`reason`. That is the point of running this as an MCP server: the model can
see *why* it was refused and act on it, instead of retrying blindly.

### Demo mode is not production

`--demo` runs with an ephemeral per-process key and in-memory state: no
configuration is read, no network call is made, and no key touches disk.
Proofs minted by a demo server verify nowhere else and do not survive a
restart. Every tool description begins with
`DEMO MODE — ephemeral key, not for production.`

`actenon_demo_grant` exists **only** in demo mode. In a real deployment the
grant comes from your authority broker ([`actenon-permit`](https://github.com/Actenon/actenon-permit))
after human approval — a verifier that issues its own authority is not a
verifier. The demo tool is there so one connected client can walk the whole
loop offline.

A production server needs signing material and **fails closed** without it:

```text
$ actenon-mcp
actenon-mcp: no signing material configured.
Non-demo mode fails closed: pass --key-file PATH, or run
  actenon-mcp --demo
for an offline demo server with an ephemeral key.
```

Demo mode is itself refused if the process looks production-like
(`ACTENON_ENV` set to anything other than `development`, `dev`, `local` or
`test`, or an Actenon production flag such as `ACTENON_PRODUCTION=1`).

A production server must also declare which capabilities it lets through
(`--capability NAME`, repeatable; protocol 13 E1) and where single-use state
lives (`ACTENON_REPLAY_DB`, a path shared by every server process):

```text
ACTENON_REPLAY_DB=/var/lib/actenon/replay.sqlite3 \
  actenon-mcp --key-file /run/secrets/actenon-mcp-key --capability payment.refund
```

An unparseable or schema-invalid `intent` or `proof` is answered with a typed
refusal (`INTENT_MALFORMED` / `PROOF_MALFORMED`) rather than a tool error, and
does not consume the proof. Arguments that fail the tool's own JSON-schema
validation are rejected by the MCP SDK before the tool runs.

## A real conversation

The transcript below is generated output, not an illustration. An agent tries
to refund $25.00, is refused, is granted authority scoped to that exact
refund, tries to widen it to $5,000.00, is refused again, retries within
scope, succeeds, replays the proof, is refused, and fetches the receipt.

```text
1. The agent attempts a $25.00 refund with no authority.
   outcome     : REFUSED
   reason_code : PCCB_REQUIRED
   reason      : The protected action did not include a proof credential block.
   next_step   : Obtain a proof scoped to this exact action from your authority broker, then call actenon_gate again.

2. A human approves authority scoped to that exact refund.
   outcome     : GRANTED
   pccb_id     : pccb_2ae82ea48d144adc8215df41de2233fe
   scoped to   : {'amount_cents': 2500, 'currency': 'USD'}

3. The agent widens the amount to $5,000.00 and presents the SAME proof and granted intent.
   outcome     : REFUSED
   reason_code : ACTION_MISMATCH
   reason      : The tool's parameters do not exactly match the supplied intent (canonical comparison; floats are never accepted).
   refusal_id  : rfsl_8d475ed4b4f044b3b4dd0e3351bc538c

4. The agent retries the refund it was actually approved for.
   outcome     : ALLOW
   reason      : The proof verified for this exact action, target, audience, scope, and time window, and single-use replay state was consumed.
   receipt_id  : rcpt_c5c6947bb5bb4294aa04185d37a2b336

5. The agent replays that same single-use proof.
   outcome     : REFUSED
   reason_code : DUPLICATE_REPLAY
   reason      : The protected action has already been claimed for execution.

6. The agent fetches the hash-chained receipt for the one refund that ran.
   reason      : Decision rcpt_c5c6947bb5bb4294aa04185d37a2b336 is entry 2 in this server's hash-chained decision log.
   artifact    : receipt rcpt_c5c6947bb5bb4294aa04185d37a2b336
   outcome     : executed
   amount      : {'amount_cents': 2500, 'currency': 'USD'}
   entry_hash  : b744819ab4bf278885bcd7c2f96cc2dc457d2203b692718fdd8b8c82c95911c6
   prev_hash   : 98251eb6bf0a4e10b6046b3edab62209bebb4c5c6b9fa7c36963473b3e5a751f
   chain_length: 4

7. The whole chain, one line per decision.
   [0] refusal  rfsl_683ba8cd9aa2431fa592e4d516b6bfa9 1a4b451b747c...
   [1] refusal  rfsl_8d475ed4b4f044b3b4dd0e3351bc538c 98251eb6bf0a...
   [2] receipt  rcpt_c5c6947bb5bb4294aa04185d37a2b336 b744819ab4bf...
   [3] refusal  rfsl_de1aee25e03a441bae6d8fe500d3e755 e85524bbfa92...
```

Step 3 is the whole product in one line. The agent held real, human-approved
authority — and still could not spend it on a different action. Note also
that every refusal is in the chain: the log records what was *attempted*, not
just what succeeded.

### Retrying with a proof

A proof is bound to one exact intent, including its identifier and time
window. When you retry, pass back the `intent` the proof was issued for:

```json
{
  "action_name": "refund.issue",
  "capability": "payments.refund",
  "parameters": {"amount_cents": 2500, "currency": "USD"},
  "target_type": "payment",
  "target_id": "pay_9f2c",
  "proof": { "...": "the proof from your broker" },
  "intent": { "...": "the intent that proof was issued for" }
}
```

Rebuilding a lookalike intent produces a new `intent_id` and is refused as
`INTENT_MISMATCH`. That is not a rough edge — it is the binding working.

The `intent` only identifies which authorisation the proof was issued for; it
never replaces the tool arguments. `action_name`, `capability`, `parameters`
(compared canonically: `2500` is not `2500.0`), `target_type`, and `target_id`
must equal the intent exactly, or the call is refused as `ACTION_MISMATCH` /
`TARGET_MISMATCH` before any replay state is consumed. Widening the amount while
passing back the granted intent is exactly the case step 3 shows.

## The Execution Gap

An unprotected MCP handler lets a model-selected tool call reach the side
effect directly:

```python
# Unprotected sketch: do not copy for consequential tools.
@server.tool("filesystem.delete")
def filesystem_delete(path: str) -> dict[str, str]:
    delete_path(path)
    return {"state": "deleted"}
```

For consequential tools, put Actenon between the tool call and the side effect:

```python
from actenon.execution import ProtectedExecutor

protected = ProtectedExecutor(proof_verifier=verifier, credential_broker=broker, outcome_writer=writer)
result = protected.execute(request, filesystem_delete_handler, policy_decision=policy_decision)
```

The protected handler receives a brokered credential reference only after the
Action Intent and PCCB verify for the exact MCP tool audience, action, target,
scope, parameters, expiry, and nonce.

## Run The Minimal Example

From the repository root:

```bash
python3 -m examples.mcp_protected_tool.demo --scenario missing-proof
python3 -m examples.mcp_protected_tool.demo --scenario allow
```

The missing-proof path refuses before the simulated tool handler runs:

```text
Outcome: REFUSED
Handler called: false
Side effect executed: false
Refusal code: PCCB_REQUIRED
Receipt outcome: refused
```

The allowed path verifies proof, brokers a local credential reference, runs the
simulated side effect, and emits an execution Receipt:

```text
Outcome: ALLOWED
Handler called: true
Side effect executed: true
Receipt outcome: executed
```

Artifacts are written locally under:

```text
artifacts/mcp_protected_tool/outcomes/receipts/
artifacts/mcp_protected_tool/outcomes/refusals/
```

## What The MCP Handler Should Do

1. Accept tool arguments plus an Action Intent and PCCB.
2. Build verifier context for the MCP tool server, not the agent.
3. Verify proof at the final tool handler before the side effect.
4. Run Preflight or endpoint policy where needed.
5. Broker credentials only after proof and policy pass.
6. Execute or refuse.
7. Emit Receipt/Refusal artifacts.

## Scanner-To-MCP Bridge

When scanner finds MCP tool side effects, wrap those handlers with the protected
executor.

Scanner output such as `MCP_TOOL_SIDE_EFFECT`, `FILE_MUTATION_SIDE_EFFECT`,
`EXTERNAL_API_SIDE_EFFECT`, or `CREDENTIAL_AUTHORITY_SIGNAL` should lead a
maintainer to ask:

```text
Can a model-selected MCP tool call reach this side effect before proof,
policy, credential brokering, replay/idempotency, and Receipt/Refusal emission?
```

If yes, move the side effect behind `ProtectedExecutor` or an equivalent
protected execution boundary.

## What This Does Not Claim

- It does not prove the upstream business decision was correct.
- It does not prove downstream provider finality.
- It does not protect side-door calls where the agent still holds raw
  production credentials.
- It does not require or imply a hosted Actenon service.

## Related Docs

- [Minimal MCP protected tool example](../../examples/mcp_protected_tool/README.md)
- [Full MCP hero path](../guides/MCP_HERO_PATH.md)
- [Credential Broker deployment](../guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
- [Scanner methodology](../guides/EXECUTION_GAP_SCANNER_METHODOLOGY.md)

