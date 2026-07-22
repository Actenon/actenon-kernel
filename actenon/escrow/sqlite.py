from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from actenon.models.contracts import format_timestamp, parse_timestamp

from .base import CapabilityEscrow, EscrowRecord


SELECT_FIELDS = """
    escrow_id,
    pccb_id,
    capability,
    expires_at,
    state,
    consumed_at,
    metadata_json
"""


def _escrow_error(refusal_code: str, message: str) -> Exception:
    from actenon.core.errors import EscrowValidationError

    return EscrowValidationError(refusal_code, message)


class SqliteCapabilityEscrow(CapabilityEscrow):
    """Durable local/dev capability escrow backed by SQLite."""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 30.0) -> None:
        self.database_path = Path(database_path)
        self.timeout_seconds = timeout_seconds
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with self._connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS capability_escrow (
                    escrow_id TEXT PRIMARY KEY,
                    pccb_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    consumed_at TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_capability_escrow_state_expiry
                ON capability_escrow (state, expires_at)
                """
            )
            connection.commit()

    def issue(
        self,
        *,
        escrow_id: str,
        pccb_id: str,
        capability: str,
        expires_at: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> EscrowRecord:
        now_raw = format_timestamp(datetime.now(timezone.utc))
        with self._connect() as connection:
            cursor = connection.cursor()
            try:
                self._prepare_transaction(cursor)
                cursor.execute(
                    """
                    INSERT INTO capability_escrow (
                        escrow_id,
                        pccb_id,
                        capability,
                        expires_at,
                        state,
                        consumed_at,
                        metadata_json,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        escrow_id,
                        pccb_id,
                        capability,
                        format_timestamp(expires_at.astimezone(timezone.utc)),
                        "issued",
                        None,
                        json.dumps(dict(metadata or {}), sort_keys=True, separators=(",", ":")),
                        now_raw,
                        now_raw,
                    ),
                )
                connection.commit()
            except Exception as exc:
                connection.rollback()
                if isinstance(exc, sqlite3.IntegrityError):
                    raise _escrow_error("ESCROW_ALREADY_EXISTS", "The escrow record already exists.") from exc
                raise
        issued = self.inspect(escrow_id)
        if issued is None:  # pragma: no cover - defensive consistency check
            raise RuntimeError(f"escrow record {escrow_id!r} was written but could not be reloaded")
        return issued

    def inspect(self, escrow_id: str) -> EscrowRecord | None:
        with self._connect() as connection:
            cursor = connection.cursor()
            row = self._select_row(cursor, escrow_id)
            if row is None:
                return None
            return self._row_to_record(row)

    def consume(self, *, escrow_id: str, pccb_id: str, capability: str, now: datetime) -> EscrowRecord:
        now_utc = now.astimezone(timezone.utc)
        now_raw = format_timestamp(now_utc)
        with self._connect() as connection:
            cursor = connection.cursor()
            self._prepare_transaction(cursor)
            row = self._select_row(cursor, escrow_id)
            if row is None:
                connection.rollback()
                raise _escrow_error("ESCROW_NOT_FOUND", "The escrow record does not exist.")
            record = self._row_to_record(row)
            if record.state == "revoked":
                connection.rollback()
                raise _escrow_error("ESCROW_REVOKED", "The escrow record has been revoked.")
            if record.state == "consumed":
                connection.rollback()
                raise _escrow_error("ESCROW_ALREADY_CONSUMED", "The escrow record has already been consumed.")
            if record.state == "expired":
                connection.rollback()
                raise _escrow_error("ESCROW_EXPIRED", "The escrow record has expired.")
            if now_utc > record.expires_at:
                cursor.execute(
                    """
                    UPDATE capability_escrow
                    SET state = ?, updated_at = ?
                    WHERE escrow_id = ?
                      AND state = ?
                    """,
                    ("expired", now_raw, escrow_id, "issued"),
                )
                connection.commit()
                raise _escrow_error("ESCROW_EXPIRED", "The escrow record has expired.")
            if record.pccb_id != pccb_id:
                connection.rollback()
                raise _escrow_error("ESCROW_PCCB_MISMATCH", "The escrow record does not match the proof.")
            if record.capability != capability:
                connection.rollback()
                raise _escrow_error(
                    "ESCROW_CAPABILITY_MISMATCH",
                    "The escrow record does not match the requested capability.",
                )
            cursor.execute(
                """
                UPDATE capability_escrow
                SET state = ?, consumed_at = ?, updated_at = ?
                WHERE escrow_id = ?
                  AND state = ?
                """,
                ("consumed", now_raw, now_raw, escrow_id, "issued"),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                current = self.inspect(escrow_id)
                if current is not None and current.state == "consumed":
                    raise _escrow_error("ESCROW_ALREADY_CONSUMED", "The escrow record has already been consumed.")
                raise _escrow_error(
                    "ESCROW_STATE_INVALID",
                    "The escrow record could not transition to consumed.",
                )
            connection.commit()
        consumed = self.inspect(escrow_id)
        if consumed is None:  # pragma: no cover - defensive consistency check
            raise RuntimeError(f"escrow record {escrow_id!r} was consumed but could not be reloaded")
        return consumed

    def revoke(self, escrow_id: str, *, reason: str) -> EscrowRecord:
        with self._connect() as connection:
            cursor = connection.cursor()
            self._prepare_transaction(cursor)
            row = self._select_row(cursor, escrow_id)
            if row is None:
                connection.rollback()
                raise _escrow_error("ESCROW_NOT_FOUND", "The escrow record does not exist.")
            record = self._row_to_record(row)
            cursor.execute(
                """
                UPDATE capability_escrow
                SET state = ?, metadata_json = ?, updated_at = ?
                WHERE escrow_id = ?
                """,
                (
                    "revoked",
                    json.dumps(
                        {**record.metadata, "revocation_reason": reason},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    format_timestamp(datetime.now(timezone.utc)),
                    escrow_id,
                ),
            )
            connection.commit()
        revoked = self.inspect(escrow_id)
        if revoked is None:  # pragma: no cover - defensive consistency check
            raise RuntimeError(f"escrow record {escrow_id!r} was revoked but could not be reloaded")
        return revoked

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=self.timeout_seconds,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
        return connection

    def _prepare_transaction(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("BEGIN IMMEDIATE")

    def _select_row(self, cursor: sqlite3.Cursor, escrow_id: str) -> sqlite3.Row | None:
        cursor.execute(
            f"""
            SELECT {SELECT_FIELDS}
            FROM capability_escrow
            WHERE escrow_id = ?
            """,
            (escrow_id,),
        )
        return cursor.fetchone()

    def _row_to_record(self, row: sqlite3.Row) -> EscrowRecord:
        consumed_at_raw = row["consumed_at"]
        metadata_raw = row["metadata_json"]
        return EscrowRecord(
            escrow_id=row["escrow_id"],
            pccb_id=row["pccb_id"],
            capability=row["capability"],
            expires_at=parse_timestamp(row["expires_at"], "expires_at"),
            state=row["state"],
            consumed_at=parse_timestamp(consumed_at_raw, "consumed_at") if consumed_at_raw else None,
            metadata=json.loads(metadata_raw) if metadata_raw else {},
        )
