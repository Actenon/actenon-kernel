# Protected Edge Templates

These templates show the resource-owner adoption pattern for database,
payment HTTP API, cloud, IAM, storage, CI/CD, communications, and physical/OT
boundaries. They are deterministic local examples and do not call providers or
perform real destructive actions.

Each template:

- builds the `ActionIntent` from the complete raw agent request
- requires `action.parameters` to bind that request exactly
- verifies proof and single-use state before acquiring a credential
- gives the backend only the verified intent and brokered credential

Use `edge.intent_for(raw_request)` when requesting or minting a proof, then
submit the same raw request to `edge.execute(raw_request, proof)`. See
[Edge Deployment](../../docs/guides/EDGE_DEPLOYMENT.md) before deploying a
resource-side boundary.
