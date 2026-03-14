# ================================================================
# MODULE: quantum_mechanic.core.store.evidence
# ----------------------------------------------------------------
# PURPOSE:   Evidence and API-log write/read operations for a
#            workspace. Extracted from workspace.py (RC-2).
# ================================================================

from __future__ import annotations

import logging
from datetime import UTC, datetime

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


class EvidenceStore:
    """Evidence and API-log operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    # ================================================================
    # Evidence
    # ================================================================

    def save(
        self,
        technique_id: str,
        output_json: str,
        credential_id: int | None = None,
    ) -> int:
        """Save the raw JSON output of a technique to the evidence table.

        Returns:
            The ID of the new evidence entry.

        DB-1 AUDIT: see CredentialStore.add — single-connection, single-threaded.
        """
        now = datetime.now(UTC).isoformat()
        cursor = self._db.execute(
            """
            INSERT INTO evidence
                (workspace_id, technique_id, credential_id, timestamp, output_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (self._workspace_id, technique_id, credential_id, now, output_json),
        )
        self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def list(self) -> list[dict]:
        """Return all evidence rows ordered by timestamp ascending.

        Used by attack_path.py to build the technique timeline.
        """
        rows = self._db.fetchall(
            """
            SELECT id, timestamp, technique_id, credential_id, output_json
            FROM evidence
            WHERE workspace_id = ?
            ORDER BY timestamp ASC
            """,
            (self._workspace_id,),
        )
        return [dict(r) for r in rows]

    # ================================================================
    # API log
    # ================================================================

    def log_api_call(
        self,
        provider: str,
        action: str,
        credential_id: int | None = None,
        service: str | None = None,
        request_params: str | None = None,
        response_status: int | None = None,
        response_summary: str | None = None,
        technique_id: str | None = None,
        duration_ms: int | None = None,
    ) -> int:
        """Append an API call to the audit log.

        Returns:
            The ID of the new log entry.

        DB-1 AUDIT: see CredentialStore.add — single-connection, single-threaded.
        """
        now = datetime.now(UTC).isoformat()
        cursor = self._db.execute(
            """
            INSERT INTO api_log
                (timestamp, credential_id, provider, service, action,
                 request_params, response_status, response_summary,
                 technique_id, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now, credential_id, provider, service, action,
                request_params, response_status, response_summary,
                technique_id, duration_ms,
            ),
        )
        self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]
