# Hello Protected Endpoint

This is the smallest Actenon protected-endpoint example.

It is designed for skeptical engineers who want to see the core primitive without learning MCP first.

The point is simple:

> The endpoint must verify proof before the side effect executes.

## What this example shows

- An untrusted caller asks for a consequential action.
- The protected endpoint checks for proof.
- If proof is missing or invalid, the endpoint refuses before the side effect.
- If proof is valid, the endpoint executes once and emits a receipt.

## Trust boundary

The agent is not trusted.

The SDK or helper is not the trust boundary.

The protected endpoint is the enforcement boundary.

```text
Untrusted caller
  ↓
Protected endpoint
  ↓
Verify proof
  ↓
Refuse or execute
  ↓
Refusal or Receipt
