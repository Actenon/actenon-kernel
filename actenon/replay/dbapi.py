from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from actenon.core.errors import ReplayValidationError
from actenon.models.contracts import format_timestamp, parse_timestamp
from .base import ActionConsumptionClaim, ActionConsumptionState, ReplayStore


SELECT_FIELDS = """
    replay_key,
    intent_id,
    pccb_id,
    nonce,
    action_hash,
    audience,
    capability,
    tenant_id,
    subject_id,
    status,
    created_at,
    updated_at,
    expires_at,
    consumed_at,
    metadata_json
"""


class DbApiReplayStore(ReplayStore):
    """Production-oriented abstraction for transactional relational replay stores."""

    parameter_placeholder = "?"

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self._connection_factory = connection_factory
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                self._sql(
                    """
                    CREATE TABLE IF NOT EXISTS action_consumption (
                        replay_key TEXT PRIMARY KEY,
                        intent_id TEXT,
                        pccb_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        action_hash TEXT NOT NULL,
                        audience TEXT NOT NULL,
                        capability TEXT NOT NULL,
                        tenant_id TEXT,
                        subject_id TEXT,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        consumed_at TEXT,
                        metadata_json TEXT NOT NULL
                    )
                    """
                )
            )
            cursor.execute(
                self._sql(
                    """
                    CREATE INDEX IF NOT EXISTS idx_action_consumption_status_expiry
                    ON action_consumption (status, expires_at)
                    """
                )
            )
            connection.commit()

    def claim_once(self, claim: ActionConsumptionClaim, *, now: datetime) -> ActionConsumptionState:
        now_utc = now.astimezone(timezone.utc)
        now_raw = format_timestamp(now_utc)
        with self._connect() as connection:
            cursor = connection.cursor()
            try:
                self._prepare_transaction(cursor)
                cursor.execute(
                    self._sql(
                        """
                        UPDATE action_consumption
                        SET status = ?, updated_at = ?
                        WHERE replay_key = ?
                          AND status = ?
                          AND expires_at <= ?
                        """,
                    ),
                    ("expired", now_raw, claim.replay_key, "claimed", now_raw),
                )
                cursor.execute(
                    self._sql(
                        """
                        DELETE FROM action_consumption
                        WHERE replay_key = ?
                          AND status IN (?, ?)
                        """,
                    ),
                    (claim.replay_key, "released", "expired"),
                )
                cursor.execute(
                    self._sql(
                        """
                        INSERT INTO action_consumption (
                            replay_key,
                            intent_id,
                            pccb_id,
                            nonce,
                            action_hash,
                            audience,
                            capability,
                            tenant_id,
                            subject_id,
                            status,
                            created_at,
                            updated_at,
                            expires_at,
                            consumed_at,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    ),
                    (
                        claim.replay_key,
                        claim.intent_id,
                        claim.pccb_id,
                        claim.nonce,
                        claim.action_hash,
                        claim.audience,
                        claim.capability,
                        claim.tenant_id,
                        claim.subject_id,
                        "claimed",
                        now_raw,
                        now_raw,
                        format_timestamp(claim.expires_at),
                        None,
                        json.dumps(claim.metadata, sort_keys=True, separators=(",", ":")),
                    ),
                )
                connection.commit()
            except Exception as exc:
                if self._is_integrity_error(exc):
                    connection.rollback()
                    existing = self.inspect(claim.replay_key, now=now_utc)
                    status = existing.status if existing else "unknown"
                    raise ReplayValidationError(
                        "DUPLICATE_REPLAY",
                        "The protected action has already been claimed for execution.",
                        details={
                            "replay_key": claim.replay_key,
                            "existing_status": status,
                            "pccb_id": claim.pccb_id,
                        },
                    ) from exc
                connection.rollback()
                raise
        return self.inspect(claim.replay_key, now=now_utc)  # type: ignore[return-value]

    def mark_consumed(self, replay_key: str, *, now: datetime) -> ActionConsumptionState:
        now_utc = now.astimezone(timezone.utc)
        now_raw = format_timestamp(now_utc)
        with self._connect() as connection:
            cursor = connection.cursor()
            self._prepare_transaction(cursor)
            cursor.execute(
                self._sql(
                    """
                    UPDATE action_consumption
                    SET status = ?, updated_at = ?, consumed_at = ?
                    WHERE replay_key = ?
                      AND status = ?
                    """,
                ),
                ("consumed", now_raw, now_raw, replay_key, "claimed"),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                existing = self.inspect(replay_key, now=now_utc)
                details = {"replay_key": replay_key}
                if existing is not None:
                    details["existing_status"] = existing.status
                raise ReplayValidationError(
                    "REPLAY_STATE_INVALID",
                    "The replay record could not transition to consumed.",
                    details=details,
                )
            connection.commit()
        return self.inspect(replay_key, now=now_utc)  # type: ignore[return-value]

    def release_claim(self, replay_key: str, *, now: datetime, reason: str) -> ActionConsumptionState:
        now_utc = now.astimezone(timezone.utc)
        now_raw = format_timestamp(now_utc)
        with self._connect() as connection:
            cursor = connection.cursor()
            self._prepare_transaction(cursor)
            existing = self._select_row(cursor, replay_key)
            if existing is None:
                connection.rollback()
                raise ReplayValidationError(
                    "REPLAY_CLAIM_MISSING",
                    "The replay claim does not exist.",
                    details={"replay_key": replay_key},
                )
            current = self._row_to_state(existing)
            if current.status == "consumed":
                connection.rollback()
                return current
            metadata = {**current.metadata, "release_reason": reason}
            cursor.execute(
                self._sql(
                    """
                    UPDATE action_consumption
                    SET status = ?, updated_at = ?, metadata_json = ?
                    WHERE replay_key = ?
                      AND status = ?
                    """,
                ),
                ("released", now_raw, json.dumps(metadata, sort_keys=True, separators=(",", ":")), replay_key, "claimed"),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise ReplayValidationError(
                    "REPLAY_RELEASE_INVALID",
                    "The replay claim could not be released.",
                    details={"replay_key": replay_key, "existing_status": current.status},
                )
            connection.commit()
        return self.inspect(replay_key, now=now_utc)  # type: ignore[return-value]

    def inspect(self, replay_key: str, *, now: datetime | None = None) -> ActionConsumptionState | None:
        now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        with self._connect() as connection:
            cursor = connection.cursor()
            row = self._select_row(cursor, replay_key)
            if row is None:
                return None
            state = self._row_to_state(row)
            if state.status == "claimed" and state.expires_at <= now_utc:
                cursor.execute(
                    self._sql(
                        """
                        UPDATE action_consumption
                        SET status = ?, updated_at = ?
                        WHERE replay_key = ?
                          AND status = ?
                        """,
                    ),
                    ("expired", format_timestamp(now_utc), replay_key, "claimed"),
                )
                connection.commit()
                row = self._select_row(cursor, replay_key)
                if row is None:
                    return None
                state = self._row_to_state(row)
            return state

    def purge_expired(self, *, now: datetime) -> int:
        now_raw = format_timestamp(now.astimezone(timezone.utc))
        with self._connect() as connection:
            cursor = connection.cursor()
            self._prepare_transaction(cursor)
            cursor.execute(
                self._sql(
                    """
                    UPDATE action_consumption
                    SET status = ?, updated_at = ?
                    WHERE status = ?
                      AND expires_at <= ?
                    """,
                ),
                ("expired", now_raw, "claimed", now_raw),
            )
            count = cursor.rowcount
            connection.commit()
        return count

    def _connect(self):
        return self._connection_factory()

    def _sql(self, statement: str) -> str:
        if self.parameter_placeholder == "?":
            return statement
        return statement.replace("?", self.parameter_placeholder)

    def _prepare_transaction(self, cursor: Any) -> None:
        """Backends may override this for stronger claim/consume isolation."""

    def _is_integrity_error(self, exc: Exception) -> bool:
        return any(cls.__name__.lower().endswith("integrityerror") for cls in type(exc).__mro__)

    def _select_row(self, cursor: Any, replay_key: str) -> Any:
        cursor.execute(
            self._sql(f"SELECT {SELECT_FIELDS} FROM action_consumption WHERE replay_key = ?"),
            (replay_key,),
        )
        return cursor.fetchone()

    def _row_to_state(self, row: Any) -> ActionConsumptionState:
        values = list(row)
        metadata = json.loads(values[14]) if values[14] else {}
        consumed_at = parse_timestamp(values[13], "consumed_at") if values[13] else None
        return ActionConsumptionState(
            replay_key=values[0],
            intent_id=values[1],
            pccb_id=values[2],
            nonce=values[3],
            action_hash=values[4],
            audience=values[5],
            capability=values[6],
            tenant_id=values[7],
            subject_id=values[8],
            status=values[9],
            created_at=parse_timestamp(values[10], "created_at"),
            updated_at=parse_timestamp(values[11], "updated_at"),
            expires_at=parse_timestamp(values[12], "expires_at"),
            consumed_at=consumed_at,
            metadata=metadata,
        )
