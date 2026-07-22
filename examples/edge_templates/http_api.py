"""Payment HTTP API edge: destination and amount are bound from the request."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="payment.release",
        capability="payment.release",
        target_type="payment_destination",
        target_key="destination",
    )
