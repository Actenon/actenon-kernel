# Express Protected Route Example

This example shows a minimal Express route that verifies proof at the HTTP boundary before allowing a protected action.

It stays verifier-only:

1. accept optional `intent` and `pccb` JSON in the request body
2. fall back to the local proof fixture if the body omits them
3. verify proof before the protected action runs
4. return a receipt on success or a refusal plus refused receipt on failure

## Files

- `server.ts`
- `package.json`

## Install

```bash
cd examples/express_protected_route
npm install
```

## Run

```bash
npm start
```

Then call it:

```bash
curl -X POST http://127.0.0.1:3000/protected-resource \
  -H 'content-type: application/json' \
  -d '{}'
```

## Where Verification Happens

Proof verification happens inside `server.ts` before the protected route executes the hello-world action:

- `examples/express_protected_route/server.ts`
- `sdk/typescript/src/verifier.ts`

## Receipt And Refusal Handling

The route returns:

- `protected_response` and `receipt` on success
- `refusal` and refused `receipt` with HTTP `403` when verification fails
- HTTP `400` for malformed payloads

The example reuses the local proof fixture from:

- `sdk/typescript/fixtures/portable-local-proof/`

## Boundary

This example demonstrates verifier-edge protection only. It does not add orchestration, approval routing, or any hosted control plane.
