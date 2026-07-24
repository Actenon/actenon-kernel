# Production Reference Deployment

> A reference deployment of the Actenon kernel that does NOT require
> actenon-cloud. Docker-compose with the kernel and a Postgres replay
> store, plus a worked example protecting one endpoint end to end.
>
> This is an Apache-2.0 reference. Every step here was executed.

## What this demonstrates

1. The kernel verifier running in a container.
2. A Postgres replay store (durable, multi-instance-capable).
3. One protected endpoint that requires a valid PCCB to execute.
4. A full mint → verify → execute → receipt cycle.

## Prerequisites

- Docker and Docker Compose
- Python 3.10+ (for the client script)

## Bring it up

```bash
cd examples/production-reference
docker compose up -d
```

This starts:
- `db` — Postgres 16 for the replay store
- `verifier` — the kernel verifier service (FastAPI)

## Verify one protected request end to end

```bash
python client.py
```

This script:
1. Mints a PCCB for a `payment.refund` action.
2. Sends the PCCB + intent to the protected endpoint.
3. The verifier checks the proof, claims the replay key, executes, returns a receipt.
4. Prints the receipt.

### Expected output

```
Minting PCCB...
PCCB minted: pccb_ref_001
Sending to protected endpoint...
Response: {"outcome": "executed", "receipt_id": "rcpt_..."}
Receipt verified.
```

## Tear down

```bash
docker compose down -v
```

## Files

- `docker-compose.yml` — the deployment
- `verifier_service.py` — the FastAPI service that runs the kernel
- `client.py` — the client that mints a proof and calls the endpoint
- `Dockerfile` — builds the verifier image

## What this is NOT

- This is not a production deployment. It uses the local HMAC signer
  (development-only). For production, use the KMS-backed signer (see
  `docs/PRODUCTION_INTEGRATION.md` §1.3).
- This does not include multi-tenant isolation, OIDC auth, or
  observability. Those are operator concerns; this reference shows the
  kernel's proof-verification cycle.
