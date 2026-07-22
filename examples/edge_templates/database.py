"""Database mutation edge: the table request is proof-bound before execution."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="database.delete_table",
        capability="database.delete",
        target_type="database_table",
        target_key="table",
    )
