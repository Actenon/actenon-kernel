# FastAPI Resource-Boundary Refund Example

This example shows Actenon protecting the resource/API boundary directly.

The protected resource is a fake refund endpoint:

```text
POST /refunds/{order_id}
```

Proof travels in:

```text
X-Actenon-Proof
```

The endpoint builds the exact refund action from the HTTP request and then calls:

```python
gate.protect(...)
```

The refund side effect only runs if proof is valid for the exact order, amount, tenant, requester and target audience.

---

## Why this example matters

Actenon can sit inside agent framework adapters, but it can also sit directly at the resource boundary.

That is the stronger security pattern.

Even if multiple agents, frameworks or workflows can reach the same refund API, the API itself refuses execution unless valid proof is bound to the exact action.

> Protect the boundary you own. Do not rely on the agent to be safe.

---

## Run the tests

```bash
python -m pytest examples/fastapi_resource_boundary_refund -vv
```

The tests prove:

- valid proof executes once;
- changed amount is refused before side effect;
- changed order is refused before side effect;
- missing proof is refused before side effect;
- replay is refused before the second side effect.
