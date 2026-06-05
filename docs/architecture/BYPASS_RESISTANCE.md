# Bypass Resistance

Status: deployment doctrine for credential-brokered protected execution. This document does not claim Actenon can prevent bypass paths when a deployment leaves direct production credentials available to agents.

## Core Rule

No standing agent credentials for consequential production systems.

The agent may request action. The protected endpoint brokers authority only after proof verification, replay/escrow handling, and policy checks.

## Strong Pattern

```text
agent
  -> ActionIntent/PCCB
  -> Protected Endpoint
  -> proof verification
  -> replay/escrow consumption where required
  -> Credential Broker
  -> short-lived scoped authority
  -> target system
  -> Receipt/Refusal
```

The protected endpoint is the only route to the consequential system. The agent never receives raw production provider credentials, database URLs, cloud credentials, browser session cookies, or long-lived API tokens.

## Anti-Pattern

```text
agent
  -> raw production credential
  -> target system
```

This is a bypass path. Actenon can still protect and receipt the path that reaches a protected endpoint, but it cannot stop direct execution that never crosses that boundary.

Unsafe claim:

> Actenon prevents all bypass even if the agent still holds production credentials.

Safe claim:

> The strong Actenon deployment removes standing agent credentials and routes consequential actions through a protected endpoint.

## Broker Requirements

A production credential broker should:

- release only short-lived scoped credentials
- release authority only inside the protected endpoint or equivalent boundary
- release authority only after proof verification succeeds
- release authority only after replay/escrow consumption where the route requires single-use execution
- never run on proof failure, policy refusal, replay failure, or escrow failure
- fail closed when the broker cannot acquire authority
- release or revoke brokered authority after execution or protected handler failure
- keep raw secret material out of Receipt/Refusal artifacts
- keep provider response bodies and SDK exception text out of public artifacts
- expose only safe brokered credential reference ids
- avoid leaking sensitive vault/provider topology through `secret_reference`

`BrokeredCredential.secret_reference` is a public-safe pointer, not a raw credential. It should identify the brokered grant enough for audit and cleanup without exposing vault paths, provider account internals, raw token ids, or reusable authority.

## Protected Executor Ordering

For a brokered path, the protected executor sequence is:

1. verify the exact Action Intent and PCCB
2. apply endpoint policy or Preflight-bound policy result
3. claim replay state where configured
4. consume escrow/capability state where configured
5. acquire brokered authority
6. execute the handler
7. mark replay consumed after the ambiguity boundary
8. release brokered authority
9. emit Receipt or Refusal

The broker must not be called on earlier refusal paths. Broker failure becomes
a safe Refusal and must not leak provider exception details. When broker
failure happens after replay/escrow consumption, the consumed state remains
consumed; the same proof should not be retried as if no authority may have been
used.

## Direct Credential Signals

Scanner findings should be reviewed when agent/tool paths include:

- environment secrets loaded in agent or tool modules
- API client construction inside an agent executor
- browser cookies or session-state files loaded by the agent
- cloud credentials or SDK sessions in an agent path
- database URLs or connection strings in an agent tool path
- MCP tools with direct credentials and no visible proof gate
- consequential tool paths where a Credential Broker is not visible

Static findings are advisory and require maintainer review. They are a map of potential authority, not proof that a production exploit path exists.

## Migration Pattern

During migration, a deployment may temporarily have both:

```text
agent -> protected endpoint -> target system
agent -> standing credential -> target system
```

Name this as a partial deployment. Receipts and refusals cover the protected path only. Strong bypass-resistance claims should wait until the direct credential path is removed or technically blocked.

## Related Documents

- [TECHNICAL_ARCHITECTURE.md](TECHNICAL_ARCHITECTURE.md)
- [TRUST_BOUNDARIES.md](TRUST_BOUNDARIES.md)
- [DEPLOYMENT_ARCHITECTURES.md](DEPLOYMENT_ARCHITECTURES.md)
- [REPLAY_ESCROW_CONCURRENCY.md](REPLAY_ESCROW_CONCURRENCY.md)
- [../guides/CREDENTIAL_BROKER_DEPLOYMENT.md](../guides/CREDENTIAL_BROKER_DEPLOYMENT.md)
