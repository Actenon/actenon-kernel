"""Communications edge: recipient and message request are proof-bound."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="communications.send",
        capability="communications.send",
        target_type="recipient",
        target_key="recipient",
    )
