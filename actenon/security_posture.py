"""Explicit development intent: the one gate for insecure development behaviour.

Principle: insecure development behaviour requires explicit development
intent. Without it the kernel refuses, at construction time, to silently use:

1. the public development HMAC secret (``LOCAL_PROOF_SECRET``);
2. per-process replay state behind a single-use guarantee;
3. ``replay_protection="disabled"``;
4. ``replay_store_failure="fail_open"``;
5. an ``ActenonGate`` that does not declare the capabilities its side effect
   performs (protocol 13 E1 would then compare the request with itself).

Explicit development intent is one of:

- ``ACTENON_ENV`` set to ``development``, ``dev``, ``local`` or ``test``
  (case- and whitespace-insensitive); or
- a development entry point that declares it in code
  (``ActenonGate.local_dev(...)``, ``actenon-mcp --demo``, the
  ``actenon-kernel`` demo/simulation commands, ``actenon-kernel conformance
  run``). A code-level declaration is honoured only while ``ACTENON_ENV`` is
  unset or itself a development value: an operator who set any other value
  declared a non-development environment, and that conflict fails closed.

Every other value of ``ACTENON_ENV`` -- unset, empty, ``production``,
``prd``, ``live`` or anything unrecognised -- is production-capable. This is
an allowlist of development values, not a denylist of production names.
``ACTENON_PRODUCTION`` / ``ACTENON_CI_RELEASE`` / ``ACTENON_RELEASE_BUILD``
always win over a development value.

Items 2-5 have named unsafe overrides for operators who knowingly accept a
weaker guarantee. Using one is loud (a ``RuntimeWarning`` and a log record
naming the override) and machine-visible (the downgrade is listed in the
component's ``security_downgrades``). There is no override for the public
secret: it is public, so a proof signed with it proves nothing.
"""

from __future__ import annotations

import logging
import os
import warnings
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator


ACTENON_ENV_ENV = "ACTENON_ENV"
DEVELOPMENT_ENV_VALUES = frozenset({"development", "dev", "local", "test"})
PRODUCTION_FLAG_ENVS = ("ACTENON_PRODUCTION", "ACTENON_CI_RELEASE", "ACTENON_RELEASE_BUILD")

UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY_ENV = "ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY"
UNSAFE_ALLOW_REPLAY_DISABLED_ENV = "ACTENON_UNSAFE_ALLOW_REPLAY_DISABLED"
UNSAFE_ALLOW_REPLAY_FAIL_OPEN_ENV = "ACTENON_UNSAFE_ALLOW_REPLAY_FAIL_OPEN"
UNSAFE_ALLOW_UNDECLARED_CAPABILITIES_ENV = "ACTENON_UNSAFE_ALLOW_UNDECLARED_CAPABILITIES"

DOWNGRADE_PUBLIC_DEVELOPMENT_SECRET = "public_development_secret"
DOWNGRADE_PROCESS_LOCAL_REPLAY = "process_local_replay"
DOWNGRADE_REPLAY_PROTECTION_DISABLED = "replay_protection_disabled"
DOWNGRADE_REPLAY_STORE_FAIL_OPEN = "replay_store_fail_open"
DOWNGRADE_UNDECLARED_CAPABILITIES = "undeclared_capabilities"

HOW_TO_DECLARE_DEVELOPMENT = (
    "For local development, demos or tests set ACTENON_ENV=development "
    "(or dev, local, test)."
)

_DECLARED_INTENT: ContextVar[str | None] = ContextVar("actenon_declared_development_intent", default=None)
_logger = logging.getLogger("actenon.security")


class InsecureDefaultRefusedError(RuntimeError):
    """A development-only behaviour was requested without development intent."""


class DevelopmentIntentConflictError(InsecureDefaultRefusedError):
    """A development entry point ran in an environment declared non-development."""


def _truthy(raw: str | None) -> bool:
    return raw is not None and raw.strip().lower() in {"1", "true", "yes", "on"}


def normalized_environment() -> str:
    return os.environ.get(ACTENON_ENV_ENV, "").strip().lower()


def production_flag_set() -> bool:
    return any(_truthy(os.environ.get(name)) for name in PRODUCTION_FLAG_ENVS)


def development_environment() -> bool:
    """True when ``ACTENON_ENV`` itself declares development intent."""

    return not production_flag_set() and normalized_environment() in DEVELOPMENT_ENV_VALUES


def development_intent() -> bool:
    """True when the current context has explicit development intent."""

    if production_flag_set():
        return False
    env = normalized_environment()
    if env in DEVELOPMENT_ENV_VALUES:
        return True
    return env == "" and _DECLARED_INTENT.get() is not None


def declared_development_source() -> str | None:
    return _DECLARED_INTENT.get()


@contextmanager
def explicit_development_intent(source: str) -> Iterator[None]:
    """Declare development intent for the code run inside this block.

    ``source`` names the entry point (for example ``"ActenonGate.local_dev"``)
    and appears in refusals. The declaration is scoped: it does not outlive
    the block, so a development object built here cannot unlock development
    behaviour for later production objects in the same process.
    """

    env = normalized_environment()
    if production_flag_set() or (env and env not in DEVELOPMENT_ENV_VALUES):
        flags = [name for name in PRODUCTION_FLAG_ENVS if _truthy(os.environ.get(name))]
        declared = f"ACTENON_ENV={os.environ.get(ACTENON_ENV_ENV, '')!r}" + (f" and {', '.join(flags)}" if flags else "")
        raise DevelopmentIntentConflictError(
            f"{source} is a development-only entry point, but this environment is declared "
            f"non-development ({declared}). Development behaviour is refused. "
            "Unset ACTENON_ENV or set it to development, dev, local or test to run it locally."
        )
    token = _DECLARED_INTENT.set(source)
    try:
        yield
    finally:
        _DECLARED_INTENT.reset(token)


def declare_process_development_intent(source: str) -> None:
    """Declare development intent for a whole development-only process.

    For command-line entry points whose only purpose is a local demo,
    simulation or self-test. Refused (:class:`DevelopmentIntentConflictError`)
    when ACTENON_ENV declares a non-development environment or a production
    flag is set. With ACTENON_ENV unset the process is marked
    ``ACTENON_ENV=development`` so that worker threads and child processes see
    the same intent. Library code must use :func:`explicit_development_intent`
    instead, which does not outlive its block.
    """

    with explicit_development_intent(source):
        pass
    if not os.environ.get(ACTENON_ENV_ENV, "").strip():
        os.environ[ACTENON_ENV_ENV] = "development"


def require_development_intent(what: str, *, fix: str) -> None:
    """Refuse ``what`` unless the current context has development intent."""

    if development_intent():
        return
    raise InsecureDefaultRefusedError(
        f"{what} requires explicit development intent and ACTENON_ENV="
        f"{os.environ.get(ACTENON_ENV_ENV, '<unset>')!r} declares none. {fix} {HOW_TO_DECLARE_DEVELOPMENT}"
    )


def permit_downgrade(downgrade: str, *, override_env: str, what: str, fix: str) -> str:
    """Allow a weaker guarantee only with development intent or a named override.

    Returns the downgrade name (to be recorded in ``security_downgrades``) or
    raises :class:`InsecureDefaultRefusedError`.
    """

    if development_intent():
        return downgrade
    if _truthy(os.environ.get(override_env)):
        message = (
            f"ACTENON SECURITY DOWNGRADE: {what} is enabled outside development by the unsafe "
            f"override {override_env}=1. The guarantee is weakened ({downgrade})."
        )
        warnings.warn(message, RuntimeWarning, stacklevel=3)
        _logger.warning(message)
        return downgrade
    raise InsecureDefaultRefusedError(
        f"{what} requires explicit development intent and ACTENON_ENV="
        f"{os.environ.get(ACTENON_ENV_ENV, '<unset>')!r} declares none. {fix} "
        f"{HOW_TO_DECLARE_DEVELOPMENT} To accept the weaker guarantee outside development "
        f"anyway, set {override_env}=1 (unsafe; recorded as {downgrade!r})."
    )


__all__ = [
    "DEVELOPMENT_ENV_VALUES",
    "DOWNGRADE_PROCESS_LOCAL_REPLAY",
    "DOWNGRADE_PUBLIC_DEVELOPMENT_SECRET",
    "DOWNGRADE_REPLAY_PROTECTION_DISABLED",
    "DOWNGRADE_REPLAY_STORE_FAIL_OPEN",
    "DOWNGRADE_UNDECLARED_CAPABILITIES",
    "DevelopmentIntentConflictError",
    "InsecureDefaultRefusedError",
    "PRODUCTION_FLAG_ENVS",
    "UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY_ENV",
    "UNSAFE_ALLOW_REPLAY_DISABLED_ENV",
    "UNSAFE_ALLOW_REPLAY_FAIL_OPEN_ENV",
    "UNSAFE_ALLOW_UNDECLARED_CAPABILITIES_ENV",
    "declare_process_development_intent",
    "declared_development_source",
    "development_environment",
    "development_intent",
    "explicit_development_intent",
    "normalized_environment",
    "permit_downgrade",
    "production_flag_set",
    "require_development_intent",
]
