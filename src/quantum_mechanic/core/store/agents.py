# ================================================================
# MODULE: quantum_mechanic.core.store.agents
# ----------------------------------------------------------------
# PURPOSE:   Remote agent management and task queue operations
#            for a workspace. Extracted from workspace.py (RC-2).
#
# AR-3: Dual-path — sqlite3 (default) or SQLAlchemy (QM_DATABASE_URL).
# ================================================================

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.models import Agent, Task

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class AgentStore:
    """Agent and task-queue operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id
        self._callbacks: list[Callable[[Agent], None]] = []
        self._use_orm = bool(os.environ.get("QM_DATABASE_URL"))
        if self._use_orm:
            self._init_orm(db)

    def _init_orm(self, db: Database) -> None:
        from quantum_mechanic.core.orm.engine import get_engine
        from quantum_mechanic.core.orm.session import make_session_factory

        self._engine = get_engine(sqlite_path=db.db_path)
        self._SessionLocal = make_session_factory(self._engine)

    # ----------------------------------------------------------------
    # SSE callback registration (used by qmd dashboard)
    # ----------------------------------------------------------------

    def on_update(self, cb: Callable[[Agent], None]) -> None:
        """Register a callback invoked on every agent state change."""
        self._callbacks.append(cb)

    def _notify(self, agent_id: str) -> None:
        agent = self.get(agent_id)
        if agent:
            for cb in self._callbacks:
                try:
                    cb(agent)
                except Exception as e:
                    logger.debug("Agent update callback failed for %s: %s", agent_id, e)

    # ================================================================
    # Agent lifecycle
    # ================================================================

    def register(self, agent: Agent) -> None:
        """Register or update a remote agent (upsert by agent.id)."""
        if self._use_orm:
            self._register_orm(agent)
        else:
            self._register_sqlite(agent)
        self._notify(agent.id)

    def _register_sqlite(self, agent: Agent) -> None:
        self._db.execute(
            """
            INSERT INTO agents
                (id, workspace_id, hostname, username, internal_ip, platform, arch,
                 os_version, agent_version, profile, status, latency_ms,
                 registered_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                username = excluded.username,
                internal_ip = excluded.internal_ip,
                platform = excluded.platform,
                arch = excluded.arch,
                os_version = excluded.os_version,
                agent_version = excluded.agent_version,
                profile = excluded.profile,
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                last_seen = excluded.last_seen
            """,
            (
                agent.id, self._workspace_id,
                agent.hostname, agent.username, agent.internal_ip,
                agent.platform, agent.arch, agent.os_version,
                agent.agent_version, agent.profile, agent.status,
                agent.latency_ms, agent.registered_at, agent.last_seen,
            ),
        )
        self._db.commit()

    def _register_orm(self, agent: Agent) -> None:
        from quantum_mechanic.core.orm.tables import AgentRow

        with self._SessionLocal() as session:
            existing = session.get(AgentRow, agent.id)
            if existing:
                existing.hostname = agent.hostname
                existing.username = agent.username
                existing.internal_ip = agent.internal_ip
                existing.platform = agent.platform
                existing.arch = agent.arch
                existing.os_version = agent.os_version
                existing.agent_version = agent.agent_version
                existing.profile = agent.profile
                existing.status = agent.status
                existing.latency_ms = agent.latency_ms
                existing.last_seen = agent.last_seen
            else:
                session.add(
                    AgentRow(
                        id=agent.id,
                        workspace_id=self._workspace_id,
                        hostname=agent.hostname,
                        username=agent.username,
                        internal_ip=agent.internal_ip,
                        platform=agent.platform,
                        arch=agent.arch,
                        os_version=agent.os_version,
                        agent_version=agent.agent_version,
                        profile=agent.profile,
                        status=agent.status,
                        latency_ms=agent.latency_ms,
                        registered_at=agent.registered_at,
                        last_seen=agent.last_seen,
                    )
                )
            session.commit()

    def heartbeat(self, agent_id: str, latency_ms: int) -> None:
        """Record an agent heartbeat — refreshes last_seen + resets to active."""
        now = datetime.now(UTC).isoformat()
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import AgentRow

            with self._SessionLocal() as session:
                row = session.get(AgentRow, agent_id)
                if row:
                    row.last_seen = now
                    row.latency_ms = latency_ms
                    row.status = "active"
                    session.commit()
        else:
            self._db.execute(
                "UPDATE agents SET last_seen = ?, latency_ms = ?, status = 'active' WHERE id = ?",
                (now, latency_ms, agent_id),
            )
            self._db.commit()
        self._notify(agent_id)

    def deregister(self, agent_id: str) -> None:
        """Mark an agent inactive (graceful shutdown)."""
        self._set_status(agent_id, "inactive")
        self._notify(agent_id)

    def revoke(self, agent_id: str) -> None:
        """Revoke an agent — future connections will be refused."""
        self._set_status(agent_id, "revoked")
        self._notify(agent_id)

    def _set_status(self, agent_id: str, status: str) -> None:
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import AgentRow

            with self._SessionLocal() as session:
                row = session.get(AgentRow, agent_id)
                if row:
                    row.status = status
                    session.commit()
        else:
            self._db.execute(
                "UPDATE agents SET status = ? WHERE id = ?", (status, agent_id)
            )
            self._db.commit()

    def get(self, agent_id: str) -> Agent | None:
        """Retrieve an agent by ID."""
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import AgentRow

            with self._SessionLocal() as session:
                row = session.get(AgentRow, agent_id)
                if row is None:
                    return None
                return self._orm_to_agent(row)
        row = self._db.fetchone("SELECT * FROM agents WHERE id = ?", (agent_id,))
        if row is None:
            return None
        return self._row_to_agent(row)

    def list_ids(self) -> list[str]:
        """Return all agent IDs ordered by last_seen descending."""
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import AgentRow

            with self._SessionLocal() as session:
                rows = session.query(AgentRow.id).order_by(AgentRow.last_seen.desc()).all()
                return [r[0] for r in rows]
        rows = self._db.fetchall("SELECT id FROM agents ORDER BY last_seen DESC")
        return [r["id"] for r in rows]

    def list_stale(self, before_iso: str) -> list[dict]:
        """Return active agents whose last_seen is before the given ISO timestamp.

        Used by the receiver lifecycle monitor to detect missed heartbeats.
        """
        if self._use_orm:
            from sqlalchemy import select

            from quantum_mechanic.core.orm.tables import AgentRow
            with self._SessionLocal() as session:
                stmt = select(AgentRow).where(
                    AgentRow.workspace_id == self._workspace_id,
                    AgentRow.status == 'active',
                    AgentRow.last_seen < before_iso
                )
                rows = session.scalars(stmt).all()
                return [{"id": r.id, "last_seen": r.last_seen} for r in rows]

        rows = self._db.fetchall(
            "SELECT id, last_seen FROM agents WHERE workspace_id = ? AND status = 'active' AND last_seen < ?",
            (self._workspace_id, before_iso),
        )
        return [dict(r) for r in rows]

    # ================================================================
    # Task queue
    # ================================================================

    def queue_task(self, agent_id: str, command: str, args: bytes | None = None) -> str:
        """Enqueue a task for an agent. Returns the new task UUID."""
        task_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import TaskRow

            with self._SessionLocal() as session:
                session.add(
                    TaskRow(
                        id=task_id,
                        workspace_id=self._workspace_id,
                        agent_id=agent_id,
                        command=command,
                        args=args,
                        status="pending",
                        created_at=now,
                    )
                )
                session.commit()
        else:
            self._db.execute(
                """
                INSERT INTO tasks
                    (id, workspace_id, agent_id, command, args, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (task_id, self._workspace_id, agent_id, command, args, now),
            )
            self._db.commit()
        return task_id

    def pop_tasks(self, agent_id: str) -> list[Task]:
        """Fetch all pending tasks and atomically mark them running."""
        if self._use_orm:
            return self._pop_tasks_orm(agent_id)
        return self._pop_tasks_sqlite(agent_id)

    def _pop_tasks_sqlite(self, agent_id: str) -> list[Task]:
        # ----------------------------------------------------------------
        # ATOMIC UPDATE: We mark tasks as 'running' first, then fetch.
        # This prevents the race condition where two pop_tasks() calls
        # return the same pending task.
        #
        # Requires SQLite 3.35+ for RETURNING. If older, we use a
        # transaction with a unique batch ID.
        # ----------------------------------------------------------------
        import sqlite3
        batch_id = str(uuid.uuid4())

        try:
            # Try atomic RETURNING first (modern SQLite)
            rows = self._db.fetchall(
                """
                UPDATE tasks
                SET status = 'running'
                WHERE workspace_id = ? AND agent_id = ? AND status = 'pending'
                RETURNING id, agent_id, command, args, status, output, error,
                          created_at, completed_at
                """,
                (self._workspace_id, agent_id),
            )
            self._db.commit()
        except sqlite3.OperationalError as e:
            if "RETURNING" not in str(e): raise

            # Fallback for older SQLite (3.34 and below)
            # 1. Mark with unique batch_id in one transaction
            self._db.execute(
                """
                UPDATE tasks SET status = 'running', error = ?
                WHERE workspace_id = ? AND agent_id = ? AND status = 'pending'
                """,
                (f"batch:{batch_id}", self._workspace_id, agent_id)
            )
            # 2. Fetch those specific rows
            rows = self._db.fetchall(
                """
                SELECT id, agent_id, command, args, status, output, error,
                       created_at, completed_at
                FROM tasks
                WHERE error = ?
                """,
                (f"batch:{batch_id}",)
            )
            # 3. Clean up the temporary batch marker
            self._db.execute("UPDATE tasks SET error = NULL WHERE error = ?", (f"batch:{batch_id}",))
            self._db.commit()

        tasks = []
        for r in rows:
            tasks.append(
                Task(
                    id=r["id"],
                    agent_id=r["agent_id"],
                    command=r["command"],
                    args=r["args"],
                    status="running",
                    output=r["output"],
                    error=r["error"] if not str(r["error"]).startswith("batch:") else None,
                    created_at=r["created_at"],
                    completed_at=r["completed_at"],
                )
            )
        return tasks

    def _pop_tasks_orm(self, agent_id: str) -> list[Task]:
        from sqlalchemy import select

        from quantum_mechanic.core.orm.tables import TaskRow

        with self._SessionLocal() as session:
            # Atomic SELECT FOR UPDATE (if supported by backend)
            # SQLite handles this via file-level locks on commit, but
            # we use the ORM pattern for consistency.
            stmt = (
                select(TaskRow)
                .where(
                    TaskRow.workspace_id == self._workspace_id,
                    TaskRow.agent_id == agent_id,
                    TaskRow.status == "pending",
                )
                .with_for_update()
            )
            rows = session.scalars(stmt).all()

            tasks = []
            for r in rows:
                r.status = "running"
                tasks.append(
                    Task(
                        id=r.id,
                        agent_id=r.agent_id,
                        command=r.command,
                        args=r.args,
                        status="running",
                        output=r.output,
                        error=r.error,
                        created_at=r.created_at,
                        completed_at=r.completed_at,
                    )
                )
            if tasks:
                session.commit()
        return tasks

    def process_task_response(
        self,
        task_id: str,
        success: bool,
        output: bytes | None,
        error: str | None,
    ) -> None:
        """Update a task with its final result from the agent."""
        now = datetime.now(UTC).isoformat()
        status = "completed" if success else "failed"
        if self._use_orm:
            from quantum_mechanic.core.orm.tables import TaskRow

            with self._SessionLocal() as session:
                row = session.get(TaskRow, task_id)
                if row and row.workspace_id == self._workspace_id:
                    row.status = status
                    row.output = output
                    row.error = error
                    row.completed_at = now
                    session.commit()
        else:
            self._db.execute(
                """
                UPDATE tasks
                SET status = ?, output = ?, error = ?, completed_at = ?
                WHERE id = ? AND workspace_id = ?
                """,
                (status, output, error, now, task_id, self._workspace_id),
            )
            self._db.commit()

    # ================================================================
    # Internal helpers
    # ================================================================

    def _row_to_agent(self, row) -> Agent:
        return Agent(
            id=row["id"],
            hostname=row["hostname"],
            username=row["username"],
            internal_ip=row["internal_ip"],
            platform=row["platform"],
            arch=row["arch"],
            os_version=row["os_version"],
            agent_version=row["agent_version"],
            profile=row["profile"],
            status=row["status"],
            latency_ms=row["latency_ms"],
            registered_at=row["registered_at"],
            last_seen=row["last_seen"],
        )

    def _orm_to_agent(self, row) -> Agent:
        return Agent(
            id=row.id,
            hostname=row.hostname,
            username=row.username,
            internal_ip=row.internal_ip,
            platform=row.platform,
            arch=row.arch,
            os_version=row.os_version,
            agent_version=row.agent_version,
            profile=row.profile,
            status=row.status,
            latency_ms=row.latency_ms,
            registered_at=row.registered_at,
            last_seen=row.last_seen,
        )

    def close(self) -> None:
        """Dispose of the ORM engine and nullify the session factory."""
        if hasattr(self, "_engine"):
            self._engine.dispose()
        if hasattr(self, "_SessionLocal"):
            self._SessionLocal = None  # type: ignore[assignment]
