# ================================================================
# MODULE: quantum_mechanic.core.store.activity
# ----------------------------------------------------------------
# PURPOSE:   Structured activity logging for a workspace.
#            Captures every log event from techniques for
#            transparency and debugging.
# ================================================================

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)

class ActivityStore:
    """Operations for the activity_log table."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    def add(
        self,
        technique_id: str,
        level: str,
        message: str,
        data: dict[str, Any] | None = None
    ) -> int:
        """Add a log entry to the activity log."""
        now = datetime.now(UTC).isoformat()
        data_json = json.dumps(data) if data else None
        
        row = self._db.fetchone(
            """
            INSERT INTO activity_log
                (workspace_id, technique_id, level, timestamp, message, data)
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (self._workspace_id, technique_id, level, now, message, data_json),
        )
        self._db.commit()
        return row[0] if row else 0

    def list(
        self,
        technique_id: str | None = None,
        level: str | None = None,
        limit: int = 100
    ) -> list[dict]:
        """List log entries, optionally filtered by technique or level."""
        query = "SELECT * FROM activity_log WHERE workspace_id = ?"
        params: list[Any] = [self._workspace_id]

        if technique_id:
            query += " AND technique_id = ?"
            params.append(technique_id)
        
        if level:
            query += " AND level = ?"
            params.append(level.upper())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._db.fetchall(query, tuple(params))
        return [dict(r) for r in rows]

    def close(self) -> None:
        """Cleanup any resources."""
        pass
