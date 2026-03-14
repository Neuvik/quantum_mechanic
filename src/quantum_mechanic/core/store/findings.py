# ================================================================
# MODULE: quantum_mechanic.core.store.findings
# ----------------------------------------------------------------
# PURPOSE:   Security finding persistence and retrieval for a
#            workspace. Extracted from workspace.py (RC-2).
# ================================================================

from __future__ import annotations

import logging

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


class FindingStore:
    """Security finding operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    def add(
        self,
        *,
        technique_id: str,
        tactic: str,
        title: str,
        severity: str,
        provider: str,
        description: str,
        evidence: str,
        mitre_id: str | None = None,
    ) -> int:
        """Persist a security finding derived from technique output.

        Called by the runner for each risk_flag the summarizer detects.
        Feeds list() -> attack_path.py -> ATTACK_PATH.md.

        INSERT OR IGNORE deduplicates by (technique_id, title) per the
        unique constraint on the findings table.

        DB-1 AUDIT: lastrowid is 0 when INSERT OR IGNORE silently skips a
        duplicate. Callers needing the ID of an existing row must re-query.

        Returns:
            The ID of the new (or 0 for ignored) finding row.
        """
        cursor = self._db.execute(
            """
            INSERT OR IGNORE INTO findings
                (workspace_id, technique_id, tactic, mitre_id, title,
                 severity, provider, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._workspace_id,
                technique_id,
                tactic,
                mitre_id,
                title,
                severity,
                provider,
                description,
                evidence,
            ),
        )
        self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def list(self) -> list[dict]:
        """Return all findings ordered by severity then timestamp.

        Severity order: critical > high > medium > low > other.
        Used by attack_path.py to build the findings summary.
        """
        rows = self._db.fetchall(
            """
            SELECT id, technique_id, tactic, mitre_id, title, severity,
                   provider, description, evidence, created_at
            FROM findings
            WHERE workspace_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    ELSE 5
                END,
                created_at ASC
            """,
            (self._workspace_id,),
        )
        return [dict(r) for r in rows]
