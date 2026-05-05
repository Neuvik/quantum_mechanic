# ================================================================
# MODULE: quantum_mechanic.core.store.assets
# ----------------------------------------------------------------
# PURPOSE:   Compute instance and network asset upsert/list for a
#            workspace. Extracted from workspace.py (RC-2).
#
# AR-3: Dual-path — sqlite3 (default) or SQLAlchemy (QM_DATABASE_URL).
# ================================================================

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


class AssetStore:
    """Compute and network asset operations scoped to a single workspace."""

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
    # Compute instances
    # ================================================================

    def upsert_compute_instance(
        self,
        *,
        provider: str,
        instance_id: str,
        name: str | None = None,
        state: str | None = None,
        instance_type: str | None = None,
        private_ip: str | None = None,
        public_ip: str | None = None,
        subnet_id: str | None = None,
        image_id: str | None = None,
        identity_arn: str | None = None,
        identity_name: str | None = None,
        security_group_ids: str = "[]",
        metadata: str = "{}",
    ) -> None:
        """Insert or update a compute instance record."""
        if self._use_orm:
            return self._upsert_compute_orm(
                provider=provider, instance_id=instance_id, name=name,
                state=state, instance_type=instance_type, private_ip=private_ip,
                public_ip=public_ip, subnet_id=subnet_id, image_id=image_id,
                identity_arn=identity_arn, identity_name=identity_name,
                security_group_ids=security_group_ids, metadata=metadata,
            )
        now = datetime.now(UTC).isoformat()
        self._db.execute(
            """
            INSERT INTO compute_instances
                (workspace_id, provider, instance_id, name, state,
                 instance_type, private_ip, public_ip, subnet_id,
                 image_id, identity_arn, identity_name, security_group_ids,
                 metadata, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, provider, instance_id) DO UPDATE SET
                name            = excluded.name,
                state           = excluded.state,
                instance_type   = excluded.instance_type,
                private_ip      = excluded.private_ip,
                public_ip       = excluded.public_ip,
                subnet_id       = excluded.subnet_id,
                image_id        = excluded.image_id,
                identity_arn    = excluded.identity_arn,
                identity_name   = excluded.identity_name,
                security_group_ids = excluded.security_group_ids,
                metadata        = excluded.metadata,
                last_seen       = excluded.last_seen
            """,
            (
                self._workspace_id, provider, instance_id, name, state,
                instance_type, private_ip, public_ip, subnet_id,
                image_id, identity_arn, identity_name, security_group_ids,
                metadata, now, now,
            ),
        )
        self._db.commit()

    def _upsert_compute_orm(self, **kwargs) -> None:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import ComputeInstanceRow

        now = datetime.now(UTC).isoformat()
        with self._SessionLocal() as session:
            existing = session.scalars(
                select(ComputeInstanceRow).where(
                    ComputeInstanceRow.workspace_id == self._workspace_id,
                    ComputeInstanceRow.provider == kwargs["provider"],
                    ComputeInstanceRow.instance_id == kwargs["instance_id"],
                )
            ).first()

            if existing:
                existing.name = kwargs.get("name")
                existing.state = kwargs.get("state")
                existing.instance_type = kwargs.get("instance_type")
                existing.private_ip = kwargs.get("private_ip")
                existing.public_ip = kwargs.get("public_ip")
                existing.subnet_id = kwargs.get("subnet_id")
                existing.image_id = kwargs.get("image_id")
                existing.identity_arn = kwargs.get("identity_arn")
                existing.identity_name = kwargs.get("identity_name")
                existing.security_group_ids = kwargs.get("security_group_ids", "[]")
                existing.metadata = kwargs.get("metadata", "{}")
                existing.last_seen = now
            else:
                session.add(
                    ComputeInstanceRow(
                        workspace_id=self._workspace_id,
                        provider=kwargs["provider"],
                        instance_id=kwargs["instance_id"],
                        name=kwargs.get("name"),
                        state=kwargs.get("state"),
                        instance_type=kwargs.get("instance_type"),
                        private_ip=kwargs.get("private_ip"),
                        public_ip=kwargs.get("public_ip"),
                        subnet_id=kwargs.get("subnet_id"),
                        image_id=kwargs.get("image_id"),
                        identity_arn=kwargs.get("identity_arn"),
                        identity_name=kwargs.get("identity_name"),
                        security_group_ids=kwargs.get("security_group_ids", "[]"),
                        metadata=kwargs.get("metadata", "{}"),
                        first_seen=now,
                        last_seen=now,
                    )
                )
            session.commit()

    def list_compute_instances(self, *, provider: str | None = None) -> list[dict]:
        """Return all known compute instances, optionally filtered by provider."""
        if self._use_orm:
            return self._list_compute_orm(provider=provider)
        sql = "SELECT * FROM compute_instances WHERE workspace_id = ?"
        params: list[Any] = [self._workspace_id]
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        sql += " ORDER BY provider, instance_id"
        rows = self._db.fetchall(sql, tuple(params))
        return [dict(r) for r in rows]

    def _list_compute_orm(self, *, provider: str | None) -> list[dict]:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import ComputeInstanceRow

        with self._SessionLocal() as session:
            stmt = (
                select(ComputeInstanceRow)
                .where(ComputeInstanceRow.workspace_id == self._workspace_id)
                .order_by(ComputeInstanceRow.provider, ComputeInstanceRow.instance_id)
            )
            if provider:
                stmt = stmt.where(ComputeInstanceRow.provider == provider)
            rows = session.scalars(stmt).all()
            return [
                {c.key: getattr(r, c.key) for c in ComputeInstanceRow.__table__.columns}
                for r in rows
            ]

    def close(self) -> None:
        """Dispose of the ORM engine and nullify the session factory."""
        if hasattr(self, "_engine"):
            self._engine.dispose()
        if hasattr(self, "_SessionLocal"):
            self._SessionLocal = None  # type: ignore[assignment]

    # ================================================================
    # Network assets
    # ================================================================

    def upsert_network_asset(
        self,
        *,
        provider: str,
        asset_type: str,
        asset_id: str,
        name: str | None = None,
        region: str | None = None,
        metadata: str = "{}",
    ) -> None:
        """Insert or update a network asset (subnet, SG, VPC, etc.)."""
        if self._use_orm:
            return self._upsert_network_orm(
                provider=provider, asset_type=asset_type, asset_id=asset_id,
                name=name, region=region, metadata=metadata,
            )
        now = datetime.now(UTC).isoformat()
        self._db.execute(
            """
            INSERT INTO network_assets
                (workspace_id, provider, asset_type, asset_id, name,
                 region, metadata, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, provider, asset_type, asset_id) DO UPDATE SET
                name      = excluded.name,
                region    = excluded.region,
                metadata  = excluded.metadata,
                last_seen = excluded.last_seen
            """,
            (
                self._workspace_id, provider, asset_type, asset_id, name,
                region, metadata, now, now,
            ),
        )
        self._db.commit()

    def _upsert_network_orm(self, **kwargs) -> None:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import NetworkAssetRow

        now = datetime.now(UTC).isoformat()
        with self._SessionLocal() as session:
            existing = session.scalars(
                select(NetworkAssetRow).where(
                    NetworkAssetRow.workspace_id == self._workspace_id,
                    NetworkAssetRow.provider == kwargs["provider"],
                    NetworkAssetRow.asset_type == kwargs["asset_type"],
                    NetworkAssetRow.asset_id == kwargs["asset_id"],
                )
            ).first()

            if existing:
                existing.name = kwargs.get("name")
                existing.region = kwargs.get("region")
                existing.metadata = kwargs.get("metadata", "{}")
                existing.last_seen = now
            else:
                session.add(
                    NetworkAssetRow(
                        workspace_id=self._workspace_id,
                        provider=kwargs["provider"],
                        asset_type=kwargs["asset_type"],
                        asset_id=kwargs["asset_id"],
                        name=kwargs.get("name"),
                        region=kwargs.get("region"),
                        metadata=kwargs.get("metadata", "{}"),
                        first_seen=now,
                        last_seen=now,
                    )
                )
            session.commit()
