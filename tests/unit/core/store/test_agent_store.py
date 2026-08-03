# ================================================================
# TESTS: quantum_mechanic.core.store.agents
# ----------------------------------------------------------------
# WHAT:   Isolated tests for AgentStore — agent lifecycle and
#         the task queue (queue_task, pop_tasks, process_task_response).
#
# WHY:    Task pop atomicity is critical — wrong locking would
#         cause an agent to receive the same task twice. Status
#         transitions gate the C2 control flow.
# ================================================================

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.agents import AgentStore
from quantum_mechanic.core.store.models import Agent


def _make_agent(**kwargs) -> Agent:
    """Build a valid Agent dataclass with sensible defaults."""
    from datetime import UTC, datetime
    now = datetime.now(UTC).isoformat()
    defaults = dict(
        id="agent-001",
        hostname="victim-host",
        username="ubuntu",
        internal_ip="10.0.0.5",
        platform="linux",
        arch="x86_64",
        os_version="Ubuntu 22.04",
        agent_version="0.1.0",
        profile="default",
        status="active",
        latency_ms=42,
        registered_at=now,
        last_seen=now,
    )
    defaults.update(kwargs)
    return Agent(**defaults)


@pytest.fixture
def db(workspace_db):
    return workspace_db


@pytest.fixture
def store(workspace_db, workspace_id):
    return AgentStore(workspace_db, workspace_id)


# ================================================================
# Agent lifecycle
# ================================================================

class TestAgentStoreLifecycle:
    def test_register_persists_agent(self, store):
        store.register(_make_agent())
        agent = store.get("agent-001")
        assert agent is not None
        assert agent.hostname == "victim-host"

    def test_get_missing_returns_none(self, store):
        assert store.get("nonexistent") is None

    def test_register_upserts_on_conflict(self, store):
        """Second register must update in place, not insert a new row."""
        store.register(_make_agent(hostname="old-host"))
        store.register(_make_agent(hostname="new-host"))
        agent = store.get("agent-001")
        assert agent.hostname == "new-host"

    def test_heartbeat_sets_active_status(self, store):
        store.register(_make_agent(status="inactive"))
        store.heartbeat("agent-001", latency_ms=10)
        agent = store.get("agent-001")
        assert agent.status == "active"
        assert agent.latency_ms == 10

    def test_deregister_sets_inactive(self, store):
        store.register(_make_agent())
        store.deregister("agent-001")
        assert store.get("agent-001").status == "inactive"

    def test_revoke_sets_revoked(self, store):
        store.register(_make_agent())
        store.revoke("agent-001")
        assert store.get("agent-001").status == "revoked"

    def test_callbacks_called_on_state_change(self, store):
        received = []
        store.on_update(lambda a: received.append(a.status))
        store.register(_make_agent(status="active"))
        store.deregister("agent-001")
        assert "active" in received
        assert "inactive" in received


# ================================================================
# Task queue
# ================================================================

class TestAgentStoreTaskQueue:
    def test_queue_task_returns_uuid_string(self, store):
        store.register(_make_agent())
        task_id = store.queue_task("agent-001", "shell", b"ls -la")
        assert isinstance(task_id, str)
        assert len(task_id) == 36  # uuid4 canonical form

    def test_pop_tasks_returns_pending_tasks(self, store):
        store.register(_make_agent())
        store.queue_task("agent-001", "shell", b"id")
        tasks = store.pop_tasks("agent-001")
        assert len(tasks) == 1
        assert tasks[0].command == "shell"

    def test_pop_tasks_marks_running(self, store):
        """pop_tasks must atomically mark tasks 'running'."""
        store.register(_make_agent())
        store.queue_task("agent-001", "shell", b"whoami")
        tasks = store.pop_tasks("agent-001")
        assert tasks[0].status == "running"

    def test_pop_tasks_only_returns_pending(self, store):
        """Already-running tasks must not be re-popped."""
        store.register(_make_agent())
        store.queue_task("agent-001", "shell", b"cmd1")
        store.pop_tasks("agent-001")      # first pop — marks running
        again = store.pop_tasks("agent-001")  # second pop — should be empty
        assert again == []

    def test_pop_tasks_only_for_correct_agent(self, store):
        store.register(_make_agent(id="agent-001"))
        store.register(_make_agent(id="agent-002"))
        store.queue_task("agent-001", "shell", b"cmd")
        tasks_002 = store.pop_tasks("agent-002")
        assert tasks_002 == []
        tasks_001 = store.pop_tasks("agent-001")
        assert len(tasks_001) == 1

    def test_pop_multiple_tasks_atomically(self, store):
        """All pending tasks come back in a single pop — no partial results."""
        store.register(_make_agent())
        for i in range(3):
            store.queue_task("agent-001", "shell", f"cmd{i}".encode())
        tasks = store.pop_tasks("agent-001")
        assert len(tasks) == 3
        assert all(t.status == "running" for t in tasks)

    def test_process_task_response_completed(self, store):
        store.register(_make_agent())
        task_id = store.queue_task("agent-001", "shell", b"id")
        store.pop_tasks("agent-001")
        store.process_task_response(task_id, success=True, output=b"uid=0(root)", error=None)
        # Verify via DB directly
        from quantum_mechanic.core.store.models import Task
        # No list method on AgentStore (not needed by Workspace API) so query DB
        row = store._db.fetchone("SELECT status, output FROM tasks WHERE id = ?", (task_id,))
        assert row["status"] == "completed"
        assert row["output"] == b"uid=0(root)"

    def test_process_task_response_failed(self, store):
        store.register(_make_agent())
        task_id = store.queue_task("agent-001", "shell", b"bad")
        store.pop_tasks("agent-001")
        store.process_task_response(task_id, success=False, output=None, error="timeout")
        row = store._db.fetchone("SELECT status, error FROM tasks WHERE id = ?", (task_id,))
        assert row["status"] == "failed"
        assert row["error"] == "timeout"

    def test_empty_pop_returns_empty_list(self, store):
        store.register(_make_agent())
        assert store.pop_tasks("agent-001") == []
