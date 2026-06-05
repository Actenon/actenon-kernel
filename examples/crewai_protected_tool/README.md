# CrewAI Protected Tool Example

This example shows the CrewAI integration pattern for the OSS kernel: a CrewAI `BaseTool` subclass whose `_run(...)` method is the protected execution edge.

Why CrewAI matters:

- CrewAI is a widely used multi-agent orchestration framework
- it encourages role separation, delegation, and tool use across cooperating agents
- that makes execution-boundary mistakes easier to hide unless proof verification stays inside the protected tool itself

If you are new to the kernel boundary, start here:

- [../../THE_EXECUTION_GAP.md](../../THE_EXECUTION_GAP.md)
- [../../spec/protected-endpoint/SPEC.md](../../spec/protected-endpoint/SPEC.md)

## What Changes In A Multi-Agent System

In a single-agent tool path, the main failure mode is often "verification happened upstream instead of in the tool."

In a multi-agent system, the risk gets sharper:

- one agent may inspect or summarize an Action Intent and PCCB
- another agent may decide a tool should run
- shared crew memory may make proof artifacts feel like ambient state

None of that authorizes execution.

Proof must still be verified at the protected tool boundary where the consequential action can actually happen. Agents must not casually share proof across execution boundaries as if inspection by one agent authorizes another agent's tool call.

## Where The Protected Tool Boundary Is

In this example, the protected boundary lives here:

- `examples/crewai_protected_tool/tool.py`
- specifically `ProtectedHelloCrewAITool._run(...)`

That `_run(...)` method is the last component before the protected action executes. So that is where proof verification belongs.

## What A Protected CrewAI Tool Looks Like

The example uses CrewAI's native custom-tool pattern:

```python
class ProtectedHelloCrewAITool(BaseTool):
    name = "protected_hello_read"
    description = "..."

    def _run(self, intent_json=None, pccb_json=None, audience_id=...) -> dict:
        # verify proof here
        # execute only after verification succeeds
        # return Receipt or Refusal artifacts
```

The important property is not the class shape by itself. It is that `_run(...)` verifies proof before any protected side effect.

## Files

- `tool.py`
- `requirements.txt`
- `artifacts/` after the first run

## Install

CrewAI currently requires Python `>=3.10,<3.14` and installs a broader orchestration dependency set than the smaller SDK-style examples.

```bash
cd /absolute/path/to/repo
make install
bash ./scripts/first_run.sh
cd examples/crewai_protected_tool
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run The Example

Success path:

```bash
python3 tool.py
```

Delegated-boundary refusal path:

```bash
python3 tool.py --scenario delegated-audience-mismatch
```

That refusal case models the important CrewAI insight: another agent or another execution boundary might forward proof artifacts, but this protected tool still has to verify them against its own audience before acting.

## What The Tool Returns

On success, the tool returns JSON with:

- `ok: true`
- `protected_response`
- `receipt`

On blocked execution, it returns:

- `ok: false`
- `refusal`
- refused `receipt` when the Action Intent and PCCB parsed successfully

If malformed JSON is supplied, the tool still returns a structured schema refusal and does not emit a receipt.

Local artifact copies are written under:

- `examples/crewai_protected_tool/artifacts/outcomes/receipts/`
- `examples/crewai_protected_tool/artifacts/outcomes/refusals/`

## Boundary

This is an OSS verifier-edge example only.

It does not add:

- private approval logic
- hosted orchestration services
- provider runtime operations
- control-plane behavior

The example exists to show that in CrewAI, tool collaboration does not remove the need for proof verification at the exact execution edge.
