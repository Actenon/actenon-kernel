"""CI/CD edge: the requested production deployment is proof-bound."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="deployment.promote",
        capability="deployment.promote",
        target_type="deployment_environment",
        target_key="environment",
    )
