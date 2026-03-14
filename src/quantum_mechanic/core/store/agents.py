# ================================================================
# MODULE: quantum_mechanic.core.store.agents
# ----------------------------------------------------------------
# PURPOSE:   Neutrino C2 agent management and task queue operations
#            for a workspace. Extracted from workspace.py (RC-2).
# ================================================================

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Callable

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
        """Register or update a Neutrino agent (upsert by agent.id)."""
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
        self._notify(agent.id)

    def heartbeat(self, agent_id: str, latency_ms: int) -> None:
        """Record an agent heartbeat — refreshes last_seen + resets to active."""
        now = datetime.now(UTC).isoformat()
        self._db.execute(
            "UPDATE agents SET last_seen = ?, latency_ms = ?, status = 'active' WHERE id = ?",
            (now, latency_ms, agent_id),
        )
        self._db.commit()
        self._notify(agent_id)

    def deregister(self, agent_id: str) -> None:
        """Mark an agent inactive (graceful shutdown)."""
        self._db.execute(
            "UPDATE agents SET status = 'inactive' WHERE id = ?", (agent_id,)
        )
        self._db.commit()
        self._notify(agent_id)

    def revoke(self, agent_id: str) -> None:
        """Revoke an agent — future connections will be refused."""
        self._db.execute(
            "UPDATE agents SET status = 'revoked' WHERE id = ?", (agent_id,)
        )
        self._db.commit()
        self._notify(agent_id)

    def get(self, agent_id: str) -> Agent | None:
        """Retrieve an agent by ID."""
        row = self._db.fetchone("SELECT * FROM agents WHERE id = ?", (agent_id,))
        if row is None:
            return None
        return self._row_to_agent(row)

    # ================================================================
    # Task queue
    # ================================================================

    def queue_task(self, agent_id: str, command: str, args: bytes | None = None) -> str:
        """Enqueue a task for an agent. Returns the new task UUID."""
        task_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
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
        rows = self._db.fetchall(
            """
            SELECT id, agent_id, command, args, status, output, error,
                   created_at, completed_at
            FROM tasks
            WHERE workspace_id = ? AND agent_id = ? AND status = 'pending'
            """,
            (self._workspace_id, agent_id),
        )
        tasks = []
        for r in rows:
            self._db.execute(
                "UPDATE tasks SET status = 'running' WHERE id = ?", (r["id"],)
            )
            tasks.append(
                Task(
                    id=r["id"],
                    agent_id=r["agent_id"],
                    command=r["command"],
                    args=r["args"],
                    status="running",
                    output=r["output"],
                    error=r["error"],
                    created_at=r["created_at"],
                    completed_at=r["completed_at"],
                )
            )
        if tasks:
            self._db.commit()
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
