from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from actenon.models.contracts import ActionIntent, PCCB
from actenon.models.runtime import DynamicContextInput, ProtectedExecutionRequest
from actenon.proof.canonical import sha256_hex
from .base import ActionConsumptionClaim, ActionConsumptionState, ReplayStore
from .sqlite import SqliteReplayStore


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


def build_default_replay_store(base_dir: str | Path | None = None) -> ReplayStore:
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

