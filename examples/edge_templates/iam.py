"""IAM edge: role and principal changes are bound to the raw request."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="iam.grant_role",
        capability="iam.role.grant",
        target_type="principal",
        target_key="principal_id",
    )
