# ================================================================
# MODULE: quantum_mechanic.core.store.credentials
# ----------------------------------------------------------------
# PURPOSE:   All credential CRUD operations for a workspace.
#            Extracted from workspace.py (RC-2) — Workspace
#            delegates every credential method here.
#
# DESIGN:    CredentialStore supports two query backends:
#
#            sqlite3 path (default, local/public mode):
#              No QM_DATABASE_URL set → uses Database.execute()
#              exactly as before. Zero change to existing behaviour.
#
#            SQLAlchemy path (production qmd):
#              QM_DATABASE_URL set → uses SQLAlchemy Session.
#              Enables PostgreSQL via psycopg2 driver.
#
#            Both paths expose the identical public API.
#            The backend is selected once at init time.
#
# AR-3: CredentialStore is the pilot store for the ORM migration.
# ================================================================

from __future__ import annotations

import logging
import os
from typing import Any

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.models import Credential

logger = logging.getLogger(__name__)


class CredentialStore:
    """Credential CRUD operations scoped to a single workspace.

    Supports both the legacy sqlite3 ``Database`` backend and the
    new SQLAlchemy backend (activated via ``QM_DATABASE_URL``).
    """

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

        # ----------------------------------------------------------------
        # AR-3: Choose backend at init time so the decision is made once
        # per store instance rather than on every method call.
        # ----------------------------------------------------------------
        self._use_orm = bool(os.environ.get("QM_DATABASE_URL"))
        if self._use_orm:
            self._init_orm(db)

    def _init_orm(self, db: Database) -> None:
        """Initialise the SQLAlchemy session factory."""
        from quantum_mechanic.core.orm.engine import get_engine
        from quantum_mechanic.core.orm.session import make_session_factory

        self._engine = get_engine(sqlite_path=db.db_path)
        self._SessionLocal = make_session_factory(self._engine)

    # ================================================================
    # Write operations
    # ================================================================

    def add(
        self,
        provider: str,
        credential_type: str,
        secret_data: str,
        friendly_name: str | None = None,
        principal_id: str | None = None,
        account_id: str | None = None,
        derived_from_id: int | None = None,
        expires_at: str | None = None,
        auto_refresh: bool = False,
        obtained_via: str | None = None,
        raw_data: str | None = None,
    ) -> int:
        """Insert a new credential row.

        Returns:
            The ID of the new credential.
        """
        if self._use_orm:
            return self._add_orm(
                provider=provider, credential_type=credential_type,
                secret_data=secret_data, friendly_name=friendly_name,
                principal_id=principal_id, account_id=account_id,
                derived_from_id=derived_from_id, expires_at=expires_at,
                auto_refresh=auto_refresh, obtained_via=obtained_via,
                raw_data=raw_data,
            )
        return self._add_sqlite(
            provider=provider, credential_type=credential_type,
            secret_data=secret_data, friendly_name=friendly_name,
            principal_id=principal_id, account_id=account_id,
            derived_from_id=derived_from_id, expires_at=expires_at,
            auto_refresh=auto_refresh, obtained_via=obtained_via,
            raw_data=raw_data,
        )

    def _add_sqlite(self, **kwargs) -> int:
        """sqlite3 implementation of add()."""
        row = self._db.fetchone(
            """
            INSERT INTO credentials
                (provider, credential_type, friendly_name, principal_id,
                 account_id, derived_from_id, secret_data, expires_at,
                 auto_refresh, obtained_via, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            (
                kwargs["provider"],
                kwargs["credential_type"],
                kwargs.get("friendly_name"),
                kwargs.get("principal_id"),
                kwargs.get("account_id"),
                kwargs.get("derived_from_id"),
                kwargs["secret_data"],
                kwargs.get("expires_at"),
                int(kwargs.get("auto_refresh", False)),
                kwargs.get("obtained_via"),
                kwargs.get("raw_data"),
            ),
        )
        self._db.commit()
        return row[0] if row else 0

    def _add_orm(self, **kwargs) -> int:
        """SQLAlchemy implementation of add()."""
        from quantum_mechanic.core.orm.tables import CredentialRow

        row = CredentialRow(
            provider=kwargs["provider"],
            credential_type=kwargs["credential_type"],
            secret_data=kwargs["secret_data"],
            friendly_name=kwargs.get("friendly_name"),
            principal_id=kwargs.get("principal_id"),
            account_id=kwargs.get("account_id"),
            derived_from_id=kwargs.get("derived_from_id"),
            expires_at=kwargs.get("expires_at"),
            auto_refresh=kwargs.get("auto_refresh", False),
            obtained_via=kwargs.get("obtained_via"),
            raw_data=kwargs.get("raw_data"),
        )
        with self._SessionLocal() as session:
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id  # type: ignore[return-value]

    def update_status(self, cred_id: int, status: str) -> None:
        """Update the lifecycle status of a credential."""
        if self._use_orm:
            return self._update_status_orm(cred_id, status)
        self._db.execute(
            "UPDATE credentials SET status = ? WHERE id = ?",
            (status, cred_id),
        )
        self._db.commit()

    def _update_status_orm(self, cred_id: int, status: str) -> None:
        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            if row:
                row.status = status
                session.commit()

    def update_principal(
        self, cred_id: int, principal_id: str, friendly_name: str | None = None
    ) -> None:
        """Link a credential to a discovered principal identity."""
        if self._use_orm:
            return self._update_principal_orm(cred_id, principal_id, friendly_name)
        sql = "UPDATE credentials SET principal_id = ?"
        params: list[Any] = [principal_id]
        if friendly_name:
            sql += ", friendly_name = ?"
            params.append(friendly_name)
        sql += " WHERE id = ?"
        params.append(cred_id)
        self._db.execute(sql, tuple(params))
        self._db.commit()

    def _update_principal_orm(
        self, cred_id: int, principal_id: str, friendly_name: str | None
    ) -> None:
        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            if row:
                row.principal_id = principal_id
                if friendly_name:
                    row.friendly_name = friendly_name
                session.commit()

    def update_secret(
        self, cred_id: int, secret_data: str, friendly_name: str | None = None
    ) -> None:
        """Overwrite the secret_data (and optionally friendly_name) for an existing credential."""
        if self._use_orm:
            return self._update_secret_orm(cred_id, secret_data, friendly_name)
        sql = "UPDATE credentials SET secret_data = ?"
        params: list[Any] = [secret_data]
        if friendly_name:
            sql += ", friendly_name = ?"
            params.append(friendly_name)
        sql += " WHERE id = ?"
        params.append(cred_id)
        self._db.execute(sql, tuple(params))
        self._db.commit()

    def _update_secret_orm(
        self, cred_id: int, secret_data: str, friendly_name: str | None
    ) -> None:
        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            if row:
                row.secret_data = secret_data
                if friendly_name:
                    row.friendly_name = friendly_name
                session.commit()

    def delete(self, cred_id: int) -> bool:
        """Delete a credential, NULLing api_log and derived_from_id refs.

        Returns:
            True if deleted, False if not found.
        """
        if self._use_orm:
            return self._delete_orm(cred_id)
        return self._delete_sqlite(cred_id)

    def _delete_sqlite(self, cred_id: int) -> bool:
        row = self._db.fetchone("SELECT id FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return False
        self._db.execute(
            "UPDATE api_log SET credential_id = NULL WHERE credential_id = ?",
            (cred_id,),
        )
        self._db.execute(
            "UPDATE credentials SET derived_from_id = NULL WHERE derived_from_id = ?",
            (cred_id,),
        )
        self._db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        self._db.commit()
        return True

    def _delete_orm(self, cred_id: int) -> bool:
        from sqlalchemy import update

        from quantum_mechanic.core.orm.tables import ApiLogRow, CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            if row is None:
                return False
            # NULL out api_log reference (preserve audit trail)
            session.execute(
                update(ApiLogRow)
                .where(ApiLogRow.credential_id == cred_id)
                .values(credential_id=None)
            )
            # NULL out child credentials' derived_from_id
            session.execute(
                update(CredentialRow)
                .where(CredentialRow.derived_from_id == cred_id)
                .values(derived_from_id=None)
            )
            session.delete(row)
            session.commit()
            return True

    # ================================================================
    # Read operations
    # ================================================================

    def get(self, cred_id: int) -> Credential | None:
        """Retrieve a credential by ID (without secret_data)."""
        if self._use_orm:
            return self._get_orm(cred_id)
        row = self._db.fetchone("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return None
        return self._row_to_credential(row)

    def _get_orm(self, cred_id: int) -> Credential | None:
        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            if row is None:
                return None
            return self._orm_to_credential(row)

    def get_secret(self, cred_id: int) -> str | None:
        """Retrieve the encrypted secret_data (explicit access to sensitive material)."""
        if self._use_orm:
            return self._get_secret_orm(cred_id)
        row = self._db.fetchone(
            "SELECT secret_data FROM credentials WHERE id = ?", (cred_id,)
        )
        if row is None:
            return None
        return row["secret_data"]

    def _get_secret_orm(self, cred_id: int) -> str | None:
        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            row = session.get(CredentialRow, cred_id)
            return row.secret_data if row else None

    def list(
        self, *, provider: str | None = None, status: str | None = None
    ) -> list[Credential]:
        """List credentials with optional filters."""
        if self._use_orm:
            return self._list_orm(provider=provider, status=status)
        return self._list_sqlite(provider=provider, status=status)

    def _list_sqlite(
        self, *, provider: str | None, status: str | None
    ) -> list[Credential]:
        sql = "SELECT * FROM credentials WHERE 1=1"
        params: list[Any] = []
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY id"
        rows = self._db.fetchall(sql, tuple(params))
        return [self._row_to_credential(r) for r in rows]

    def _list_orm(
        self, *, provider: str | None, status: str | None
    ) -> list[Credential]:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import CredentialRow

        with self._SessionLocal() as session:
            stmt = select(CredentialRow).order_by(CredentialRow.id)
            if provider:
                stmt = stmt.where(CredentialRow.provider == provider)
            if status:
                stmt = stmt.where(CredentialRow.status == status)
            rows = session.scalars(stmt).all()
            return [self._orm_to_credential(r) for r in rows]

    # ================================================================
    # Internal helpers
    # ================================================================

    def _row_to_credential(self, row) -> Credential:
        """Convert a sqlite3.Row to Credential dataclass."""
        return Credential(
            id=row["id"],
            provider=row["provider"],
            credential_type=row["credential_type"],
            friendly_name=row["friendly_name"],
            principal_id=row["principal_id"],
            account_id=row["account_id"],
            derived_from_id=row["derived_from_id"],
            expires_at=row["expires_at"],
            auto_refresh=bool(row["auto_refresh"]),
            status=row["status"],
            obtained_via=row["obtained_via"],
            created_at=row["created_at"],
            raw_data=row["raw_data"],
        )

    def _orm_to_credential(self, row) -> Credential:
        """Convert a CredentialRow ORM object to Credential dataclass."""
        return Credential(
            id=row.id,
            provider=row.provider,
            credential_type=row.credential_type,
            friendly_name=row.friendly_name,
            principal_id=row.principal_id,
            account_id=row.account_id,
            derived_from_id=row.derived_from_id,
            expires_at=row.expires_at,
            auto_refresh=bool(row.auto_refresh),
            status=row.status,
            obtained_via=row.obtained_via,
            created_at=row.created_at,
            raw_data=row.raw_data,
        )

    def close(self) -> None:
        """Dispose of the ORM engine and nullify the session factory."""
        if hasattr(self, "_engine"):
            self._engine.dispose()
        if hasattr(self, "_SessionLocal"):
            self._SessionLocal = None  # type: ignore[assignment]
