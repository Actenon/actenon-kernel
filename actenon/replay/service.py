from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from actenon.models.contracts import ActionIntent, PCCB
from actenon.models.runtime import DynamicContextInput, ProtectedExecutionRequest
from actenon.proof.canonical import sha256_hex
from .base import ActionConsumptionClaim, ActionConsumptionState, ReplayStore
from .sqlite import SqliteReplayStore
from actenon.security_posture import (
    DOWNGRADE_PROCESS_LOCAL_REPLAY,
    UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY_ENV,
    permit_downgrade,
)

PROCESS_LOCAL_REPLAY_FIX = (
    "Single-use needs replay state shared by every worker and surviving restarts: set "
    "ACTENON_REPLAY_DB to a durable path shared by all workers, or pass replay_protector="
    "ReplayProtector(SqliteReplayStore(path) | PostgresReplayStore(dsn))."
)


def replay_db_configured() -> bool:
    return bool(os.environ.get("ACTENON_REPLAY_DB"))


def permit_process_local_replay(component: str) -> str:
    """Refuse per-process replay state unless development intent or the override allows it.

    Returns the downgrade name to record in ``security_downgrades``.
    """

    return permit_downgrade(
        DOWNGRADE_PROCESS_LOCAL_REPLAY,
        override_env=UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY_ENV,
        what=f"{component} with per-process replay state (a single-use proof would be accepted once per worker and again after a restart)",
        fix=PROCESS_LOCAL_REPLAY_FIX,
    )


def default_replay_db_path(base_dir: str | Path | None = None) -> Path:
    configured = os.environ.get("ACTENON_REPLAY_DB")
    if configured:
        return Path(configured)
    if base_dir is not None:
        return Path(base_dir) / "replay.sqlite3"
    # Use a process-unique temp directory by default so concurrent examples
    # don't contend on the same SQLite file. Set ACTENON_REPLAY_DB or pass
    # base_dir explicitly to use a shared path.
    import tempfile
    import atexit
    tmpdir = tempfile.mkdtemp(prefix="actenon-replay-")
    atexit.register(lambda d=tmpdir: __import__("shutil").rmtree(d, ignore_errors=True))
    return Path(tmpdir) / "replay.sqlite3"


def default_replay_store_downgrades(base_dir: str | Path | None = None) -> tuple[str, ...]:
    """Downgrades implied by :func:`build_default_replay_store` for these arguments.

    Raises when the implied store is per-process and neither development
    intent nor the named unsafe override allows it.
    """

    if replay_db_configured() or base_dir is not None:
        return ()
    return (permit_process_local_replay("the default replay store"),)


def build_default_replay_store(base_dir: str | Path | None = None) -> ReplayStore:
    """Return the replay store used when none is supplied.

    ``ACTENON_REPLAY_DB`` (or an explicit ``base_dir``) selects a durable
    SQLite file. Without either the store would live in a per-process temp
    directory deleted at exit, which cannot enforce single use across workers
    or restarts; that requires explicit development intent or
    ``ACTENON_UNSAFE_ALLOW_PROCESS_LOCAL_REPLAY=1``.
    """

    default_replay_store_downgrades(base_dir)
    return SqliteReplayStore(default_replay_db_path(base_dir))


def build_replay_key(intent: ActionIntent, pccb: PCCB, context: DynamicContextInput) -> str:
    key_input = {
        "pccb_id": pccb.pccb_id,
        "intent_id": intent.intent_id,
        "nonce": pccb.nonce,
        "action_hash": pccb.action_hash.to_dict(),
        "audience": pccb.audience.to_dict(),
        "capability": intent.action.capability,
        "target": intent.target.to_dict(),
    }
    return f"rpk_{sha256_hex(key_input)}"


def build_action_consumption_claim(
    intent: ActionIntent,
    pccb: PCCB,
    context: DynamicContextInput,
) -> ActionConsumptionClaim:
    return ActionConsumptionClaim(
        replay_key=build_replay_key(intent, pccb, context),
        intent_id=intent.intent_id,
        pccb_id=pccb.pccb_id,
        nonce=pccb.nonce,
        action_hash=pccb.action_hash.value,
        audience=f"{pccb.audience.type}:{pccb.audience.id}",
        capability=intent.action.capability,
        tenant_id=intent.tenant.tenant_id,
        subject_id=intent.requester.id,
        expires_at=pccb.expires_at,
        metadata={
            "request_id": context.request_id,
            "audience_id": pccb.audience.id,
            "scope_capabilities": list(pccb.scope.capabilities),
        },
    )


@dataclass
class ReplayProtector:
    store: ReplayStore

    def claim_request(self, request: ProtectedExecutionRequest) -> ActionConsumptionState:
        claim = build_action_consumption_claim(request.intent, request.pccb, request.context)
        return self.store.claim_once(claim, now=request.context.now)

    def mark_consumed(self, replay_key: str, *, now) -> ActionConsumptionState:
        return self.store.mark_consumed(replay_key, now=now)

    def release_claim(self, replay_key: str, *, now, reason: str) -> ActionConsumptionState:
        return self.store.release_claim(replay_key, now=now, reason=reason)

