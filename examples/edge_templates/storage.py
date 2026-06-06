"""Storage edge: the exact object deletion request must carry proof."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="storage.delete_object",
        capability="storage.object.delete",
        target_type="storage_object",
        target_key="object_key",
    )
