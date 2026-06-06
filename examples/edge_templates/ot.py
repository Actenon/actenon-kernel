"""Physical/OT edge template; this local example performs no real actuation."""

from ._support import protected_edge


def build_edge(gate, backend):
    return protected_edge(
        gate,
        backend,
        action_name="ot.set_actuator",
        capability="ot.actuator.set",
        target_type="actuator",
        target_key="actuator_id",
    )
