"""Cloud mutation edge: the requested instance is the proven instance."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="cloud.terminate_instance",
        capability="cloud.instance.terminate",
        target_type="cloud_instance",
        target_key="instance_id",
    )
