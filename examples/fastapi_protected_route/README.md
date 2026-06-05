# FastAPI Protected Route Example

This example shows a minimal FastAPI route that verifies proof at the endpoint boundary before allowing a protected action.

The route stays local and bounded:

1. accept optional `intent` and `pccb` payloads in the request body
2. fall back to local proof fixtures if the body omits them
3. verify proof before the protected action runs
4. return a receipt on success or a refusal plus refused receipt on failure

## Files

- `app.py`
- `requirements.txt`
- `artifacts/` after the first request

## Install

```bash
cd examples/fastapi_protected_route
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app:app --reload
```

Then call it:

```bash
curl -X POST http://127.0.0.1:8000/protected-resource \
  -H 'content-type: application/json' \
  -d '{}'
```

## Where Verification Happens

Proof verification happens inside `execute_protected_hello`, which the route calls before returning any protected result:

- `examples/fastapi_protected_route/app.py`
- `examples/integration_support.py`

## Receipt And Refusal Handling

The route returns:

- `protected_response` and `receipt` on success
- `refusal` and refused `receipt` with HTTP `403` when verification or execution is blocked
- HTTP `400` for malformed payloads that cannot be parsed into the public contracts

Outcome artifacts are also written locally under:

- `examples/fastapi_protected_route/artifacts/outcomes/receipts/`
- `examples/fastapi_protected_route/artifacts/outcomes/refusals/`

## Boundary

This example demonstrates verifier-edge route protection only. It does not add orchestration, approval routing, or any hosted control plane.
