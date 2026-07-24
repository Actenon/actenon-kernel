# Hello World Protected Resource

## Purpose

This document describes the smallest verifier-first protected resource example included in the open layer.

Use it when you want to understand the protected-endpoint pattern without adopting the full kernel.

## Why Start Here

This is the shortest path from clone to a real Protected Endpoint check:

- local Action Intent
- local PCCB
- verifier-edge proof checking
- protected action execution only after verification
- inspectable artifacts written to disk

## Canonical Behavior Spec

The behavior this example demonstrates is standardized in [`../../../spec/protected-endpoint/SPEC.md`](../../../spec/protected-endpoint/SPEC.md).

## Code Locations

- `examples/hello_world_protected_resource_python/protected_resource.py`
- `actenon/demo/portable_local_proof.py`

## What It Demonstrates

- local Action Intent parsing
- local PCCB minting for demo purposes
- verifier SDK proof verification
- exact message binding
- protected resource execution only after successful verification
- a Protected Endpoint boundary without framework or control-plane complexity

The local proof minting in this example exists only to make the demo runnable. The protected endpoint side remains verifier-only.

## Where The Protected Endpoint Boundary Lives

In this example, the Protected Endpoint boundary is the point where `portable_local_proof` calls the verifier before invoking the protected resource handler:

- `actenon/demo/portable_local_proof.py`
- `examples/hello_world_protected_resource_python/protected_resource.py`

The protected resource does not execute because an upstream caller said "allow." It executes only after verifier-side checks pass.

## Mandatory Checks In This Example

The example verifies:

- audience
- expiry window
- exact action binding
- exact target binding
- tenant and subject binding
- action-hash integrity
- required capability scope

## Exact Local Command

```bash
python3 -m actenon.demo.portable_local_proof --artifacts-dir artifacts/portable_local_proof
```

## Standalone Proof Verification

After generating the local artifacts, verify the pair from the terminal:

The CLI requires the protected endpoint audience explicitly. It does not treat the proof's own audience field as enough local verifier context.

```bash
actenon-kernel verify-proof \
  --intent artifacts/portable_local_proof/action_intent.json \
  --pccb artifacts/portable_local_proof/pccb.json \
  --audience service:portable-hello-world-endpoint \
  --verification-time pccb-issued-at
```

## What Success Looks Like

After the command succeeds, inspect:

- `artifacts/portable_local_proof/verification_result.json`
- `artifacts/portable_local_proof/protected_resource_response.json`
- `artifacts/portable_local_proof/manifest.json`
- `artifacts/portable_local_proof/SUMMARY.txt`

## Expected Artifacts

- `artifacts/portable_local_proof/action_intent.json`
- `artifacts/portable_local_proof/pccb.json`
- `artifacts/portable_local_proof/verification_result.json`
- `artifacts/portable_local_proof/protected_resource_response.json`
- `artifacts/portable_local_proof/manifest.json`
- `artifacts/portable_local_proof/SUMMARY.txt`

## Next Paths

If you want to keep going from here:

- Python protected route: [../../../examples/fastapi_protected_route/README.md](../../../examples/fastapi_protected_route/README.md)
- Node protected route: [../../../examples/express_protected_route/README.md](../../../examples/express_protected_route/README.md)
- full integration chooser: [../../../INTEGRATIONS.md](../../../INTEGRATIONS.md)
