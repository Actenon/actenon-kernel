# Local Protected Invoice Payment Endpoint Example

This example is the local protected endpoint used by the zero-credential invoice payment proof flow.

It simulates a protected invoice payment resource entirely on local state:

- payee enrollment lookup
- batch hash validation
- invoice ownership and duplicate checks
- payment execution record creation
- reconciliation record creation
- resource version increment

No external accounts, API keys, or banking providers are required.
