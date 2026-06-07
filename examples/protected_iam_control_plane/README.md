# Evidence: a protected IAM / identity control plane

A runnable, self-verifying demonstration of agent-driven IAM, where the canonical risk is privilege escalation.

This example exercises Actenon's policy layer as well as proof-bound action binding. The access-governance policy pack requires approval evidence before privileged access is granted.

It verifies:

- low-risk grants execute
- privileged admin/production grants without approval are refused
- the same privileged grant with documented approval executes
- privilege escalation and parameter tampering are refused
- missing proof and replay are refused

## Run it

    pip install -e ".[asymmetric]"
    python examples/protected_iam_control_plane/protected_iam_control_plane.py
    echo "exit: $?"

> No valid proof, no execution.
