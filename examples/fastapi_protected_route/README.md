# FastAPI Protected Route

This example uses Actenon's native FastAPI dependency. The JSON body contains
only payout fields. The PCCB travels out-of-band in `X-Actenon-Proof`.

```python
protected_payout = gate.fastapi_dependency(
    audience="service:fastapi-payout-endpoint",
    action_builder=build_payout_intent,
    side_effect=simulate_payout,
    body_model=PayoutRequest,
)

@app.post("/payouts")
def create_payout(
    body: PayoutRequest,
    outcome: GateOutcome = Depends(protected_payout),
):
    return outcome.to_dict()
```

The dependency runs before the route handler. Missing, malformed, mismatched,
expired, or replayed proof returns HTTP `403` with the Refusal, refused Receipt,
and any Preflight `unmet_requirements`. The side effect is not reached.

## Run

Install the package and adapter:

```bash
python3 -m pip install -e ".[asymmetric,fastapi]"
python3 -m pip install uvicorn
uvicorn examples.fastapi_protected_route.app:app
```

Generate one local-only request and call the route:

```python
from fastapi.testclient import TestClient
from examples.fastapi_protected_route.app import app, build_demo_request

body, headers = build_demo_request()
response = TestClient(app).post("/payouts", json=body, headers=headers)
print(response.json())
```

The payout is a deterministic local simulation. No payment provider is called.
The local HMAC proof helper is development material, not production custody.

The adapter encodes proof as base64url JSON for the header. Production callers
can use `actenon.adapters.fastapi.encode_json_header(proof)`.
