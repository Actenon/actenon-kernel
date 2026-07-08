from __future__ import annotations

import sqlite3
from pathlib import Path

from .dbapi import DbApiReplayStore


class SqliteReplayStore(DbApiReplayStore):
    """Durable local/dev replay store backed by SQLite."""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 30.0) -> None:
        self.database_path = Path(database_path)
        self.timeout_seconds = timeout_seconds
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(self._create_connection)

    def _create_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.database_path),
            timeout=self.timeout_seconds,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
        return connection

    def _prepare_transaction(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("BEGIN IMMEDIATE")
