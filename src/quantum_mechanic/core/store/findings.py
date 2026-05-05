# ================================================================
# MODULE: quantum_mechanic.core.store.findings
# ----------------------------------------------------------------
# PURPOSE:   Security finding persistence and retrieval for a
#            workspace. Extracted from workspace.py (RC-2).
#
# AR-3: Dual-path — sqlite3 (default) or SQLAlchemy (QM_DATABASE_URL).
# ================================================================

from __future__ import annotations

import logging
import os

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)

# Severity ordering for list() — mirrors the SQL CASE expression.
_SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4}


class FindingStore:
    """Security finding operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id
        self._use_orm = bool(os.environ.get("QM_DATABASE_URL"))
        if self._use_orm:
            self._init_orm(db)

    def _init_orm(self, db: Database) -> None:
        from quantum_mechanic.core.orm.engine import get_engine
        from quantum_mechanic.core.orm.session import make_session_factory

        self._engine = get_engine(sqlite_path=db.db_path)
        self._SessionLocal = make_session_factory(self._engine)

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
        """Persist a security finding. INSERT OR IGNORE deduplicates by
        (technique_id, title).

        Returns:
            The ID of the new row, or 0 if the row was a duplicate.
        """
        if self._use_orm:
            return self._add_orm(
                technique_id=technique_id, tactic=tactic, title=title,
                severity=severity, provider=provider, description=description,
                evidence=evidence, mitre_id=mitre_id,
            )
        return self._add_sqlite(
            technique_id=technique_id, tactic=tactic, title=title,
            severity=severity, provider=provider, description=description,
            evidence=evidence, mitre_id=mitre_id,
        )

    def _add_sqlite(self, **kwargs) -> int:
        row = self._db.fetchone(
            """
            INSERT INTO findings
                (workspace_id, technique_id, tactic, mitre_id, title,
                 severity, provider, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, technique_id, title) DO NOTHING
            RETURNING id
            """,
            (
                self._workspace_id,
                kwargs["technique_id"],
                kwargs["tactic"],
                kwargs.get("mitre_id"),
                kwargs["title"],
                kwargs["severity"],
                kwargs["provider"],
                kwargs["description"],
                kwargs["evidence"],
            ),
        )
        self._db.commit()
        return row[0] if row else 0

    def _add_orm(self, **kwargs) -> int:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import FindingRow

        # Replicate INSERT OR IGNORE: check for duplicate first.
        with self._SessionLocal() as session:
            existing = session.scalars(
                select(FindingRow).where(
                    FindingRow.workspace_id == self._workspace_id,
                    FindingRow.technique_id == kwargs["technique_id"],
                    FindingRow.title == kwargs["title"],
                )
            ).first()
            if existing:
                return 0  # duplicate — matches sqlite3 INSERT OR IGNORE behaviour

            row = FindingRow(
                workspace_id=self._workspace_id,
                technique_id=kwargs["technique_id"],
                tactic=kwargs["tactic"],
                mitre_id=kwargs.get("mitre_id"),
                title=kwargs["title"],
                severity=kwargs["severity"],
                provider=kwargs["provider"],
                description=kwargs["description"],
                evidence=kwargs["evidence"],
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id  # type: ignore[return-value]

    def list(self) -> list[dict]:
        """Return all findings ordered by severity then timestamp."""
        if self._use_orm:
            return self._list_orm()
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

    def _list_orm(self) -> list[dict]:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import FindingRow

        with self._SessionLocal() as session:
            stmt = (
                select(FindingRow)
                .where(FindingRow.workspace_id == self._workspace_id)
            )
            rows = session.scalars(stmt).all()

        # Replicate the SQL CASE severity ORDER BY in Python.
        def _severity_key(r: FindingRow) -> tuple[int, str]:
            return (_SEVERITY_ORDER.get(r.severity, 5), r.created_at or "")

        rows = sorted(rows, key=_severity_key)
        return [
            {
                "id": r.id,
                "technique_id": r.technique_id,
                "tactic": r.tactic,
                "mitre_id": r.mitre_id,
                "title": r.title,
                "severity": r.severity,
                "provider": r.provider,
                "description": r.description,
                "evidence": r.evidence,
                "created_at": r.created_at,
            }
            for r in rows
        ]

    def close(self) -> None:
        """Dispose of the ORM engine and nullify the session factory."""
        if hasattr(self, "_engine"):
            self._engine.dispose()
        if hasattr(self, "_SessionLocal"):
            self._SessionLocal = None  # type: ignore[assignment]
