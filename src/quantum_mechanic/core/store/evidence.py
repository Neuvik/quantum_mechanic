# ================================================================
# MODULE: quantum_mechanic.core.store.evidence
# ----------------------------------------------------------------
# PURPOSE:   Evidence and API-log write/read operations for a
#            workspace. Extracted from workspace.py (RC-2).
#
# AR-3: Dual-path — sqlite3 (default) or SQLAlchemy (QM_DATABASE_URL).
# ================================================================

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


class EvidenceStore:
    """Evidence and API-log operations scoped to a single workspace."""

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
        """
        if self._use_orm:
            return self._save_orm(technique_id, output_json, credential_id)
        return self._save_sqlite(technique_id, output_json, credential_id)

    def _save_sqlite(
        self, technique_id: str, output_json: str, credential_id: int | None
    ) -> int:
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

    def _save_orm(
        self, technique_id: str, output_json: str, credential_id: int | None
    ) -> int:
        from quantum_mechanic.core.orm.tables import EvidenceRow

        now = datetime.now(UTC).isoformat()
        row = EvidenceRow(
            workspace_id=self._workspace_id,
            technique_id=technique_id,
            credential_id=credential_id,
            timestamp=now,
            output_json=output_json,
        )
        with self._SessionLocal() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id  # type: ignore[return-value]

    def list(self) -> list[dict]:
        """Return all evidence rows ordered by timestamp ascending."""
        if self._use_orm:
            return self._list_orm()
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

    def _list_orm(self) -> list[dict]:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import EvidenceRow

        with self._SessionLocal() as session:
            stmt = (
                select(EvidenceRow)
                .where(EvidenceRow.workspace_id == self._workspace_id)
                .order_by(EvidenceRow.timestamp.asc())
            )
            rows = session.scalars(stmt).all()
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp,
                    "technique_id": r.technique_id,
                    "credential_id": r.credential_id,
                    "output_json": r.output_json,
                }
                for r in rows
            ]

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
        """
        if self._use_orm:
            return self._log_api_orm(
                provider=provider, action=action, credential_id=credential_id,
                service=service, request_params=request_params,
                response_status=response_status, response_summary=response_summary,
                technique_id=technique_id, duration_ms=duration_ms,
            )
        return self._log_api_sqlite(
            provider=provider, action=action, credential_id=credential_id,
            service=service, request_params=request_params,
            response_status=response_status, response_summary=response_summary,
            technique_id=technique_id, duration_ms=duration_ms,
        )

    def _log_api_sqlite(self, **kwargs) -> int:
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
                now, kwargs.get("credential_id"), kwargs["provider"],
                kwargs.get("service"), kwargs["action"],
                kwargs.get("request_params"), kwargs.get("response_status"),
                kwargs.get("response_summary"), kwargs.get("technique_id"),
                kwargs.get("duration_ms"),
            ),
        )
        self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def _log_api_orm(self, **kwargs) -> int:
        from quantum_mechanic.core.orm.tables import ApiLogRow

        now = datetime.now(UTC).isoformat()
        row = ApiLogRow(
            timestamp=now,
            credential_id=kwargs.get("credential_id"),
            provider=kwargs["provider"],
            service=kwargs.get("service"),
            action=kwargs["action"],
            request_params=kwargs.get("request_params"),
            response_status=kwargs.get("response_status"),
            response_summary=kwargs.get("response_summary"),
            technique_id=kwargs.get("technique_id"),
            duration_ms=kwargs.get("duration_ms"),
        )
        with self._SessionLocal() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id  # type: ignore[return-value]
