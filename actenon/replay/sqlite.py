from __future__ import annotations

import sqlite3
import time
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
        """Create a configured SQLite connection.

        Retries on 'database is locked' during PRAGMA journal_mode=WAL
        because WAL mode change requires an exclusive lock that can
        conflict with concurrent initializers. The busy_timeout PRAGMA
        handles this for queries, but the journal_mode PRAGMA itself
        can fail before busy_timeout takes effect. We retry a few times
        with a short backoff.
        """
        max_retries = 5
        base_delay = 0.05  # 50ms

        for attempt in range(max_retries):
            connection = sqlite3.connect(
                str(self.database_path),
                timeout=self.timeout_seconds,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
                return connection
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < max_retries - 1:
                    connection.close()
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                raise

        # Should not reach here, but satisfy the type checker
        raise sqlite3.OperationalError("database is locked after retries")

    def _prepare_transaction(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("BEGIN IMMEDIATE")
