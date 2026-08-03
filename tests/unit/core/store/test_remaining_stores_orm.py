# ================================================================
# TESTS: EvidenceStore, FindingStore, AssetStore, AgentStore — ORM path
# ----------------------------------------------------------------
# WHAT:   Tests the 4 remaining stores against the SQLAlchemy backend.
#         Sets QM_DATABASE_URL=sqlite:///... via MonkeyPatch to force
#         the ORM code path for all 4 stores.
#
# WHY:    Both sqlite3 and ORM paths must pass the same invariants.
# ================================================================

import json
import uuid
from datetime import UTC, datetime

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.agents import AgentStore
from quantum_mechanic.core.store.assets import AssetStore
from quantum_mechanic.core.store.evidence import EvidenceStore
from quantum_mechanic.core.store.findings import FindingStore
from quantum_mechanic.core.store.models import Agent


# ================================================================
# Shared fixtures
# ================================================================

@pytest.fixture
def orm_db(tmp_path):
    db = Database.create("orm4-test", tmp_path)
    return db


@pytest.fixture
def orm_ws_id(orm_db):
    row = orm_db.fetchone("SELECT id FROM workspace WHERE name = 'orm4-test'")
    return row["id"]


@pytest.fixture
def orm_url(orm_db):
    return f"sqlite:///{orm_db.db_path}"


@pytest.fixture
def ev_store(orm_db, orm_ws_id, orm_url, monkeypatch):
    monkeypatch.setenv("QM_DATABASE_URL", orm_url)
    store = EvidenceStore(orm_db, orm_ws_id)
    yield store
    orm_db.close()


@pytest.fixture
def fi_store(orm_db, orm_ws_id, orm_url, monkeypatch):
    monkeypatch.setenv("QM_DATABASE_URL", orm_url)
    store = FindingStore(orm_db, orm_ws_id)
    yield store
    orm_db.close()


@pytest.fixture
def as_store(orm_db, orm_ws_id, orm_url, monkeypatch):
    monkeypatch.setenv("QM_DATABASE_URL", orm_url)
    store = AssetStore(orm_db, orm_ws_id)
    yield store
    orm_db.close()


@pytest.fixture
def ag_store(orm_db, orm_ws_id, orm_url, monkeypatch):
    monkeypatch.setenv("QM_DATABASE_URL", orm_url)
    store = AgentStore(orm_db, orm_ws_id)
    yield store
    orm_db.close()


def _agent(
    agent_id: str | None = None,
    *,
    status: str = "active",
    latency_ms: int = 10,
) -> Agent:
    now = datetime.now(UTC).isoformat()
    return Agent(
        id=agent_id or str(uuid.uuid4()),
        hostname="host-a",
        username="root",
        internal_ip="10.0.0.1",
        platform="linux",
        arch="x86_64",
        os_version="Ubuntu 22.04",
        agent_version="0.1.0",
        profile="default",
        status=status,
        latency_ms=latency_ms,
        registered_at=now,
        last_seen=now,
    )


# ================================================================
# EvidenceStore — ORM path
# ================================================================

class TestEvidenceStoreORM:
    def test_save_returns_integer_id(self, ev_store):
        eid = ev_store.save("aws/enum_iam", '{"result": []}')
        assert isinstance(eid, int) and eid >= 1

    def test_saved_evidence_appears_in_list(self, ev_store):
        ev_store.save("aws/enum_iam", '{"result": []}')
        rows = ev_store.list()
        assert len(rows) == 1
        assert rows[0]["technique_id"] == "aws/enum_iam"

    def test_list_ordered_by_timestamp_ascending(self, ev_store):
        ev_store.save("aws/step1", "{}")
        ev_store.save("aws/step2", "{}")
        rows = ev_store.list()
        assert rows[0]["technique_id"] == "aws/step1"
        assert rows[1]["technique_id"] == "aws/step2"

    def test_empty_list_on_empty_store(self, ev_store):
        assert ev_store.list() == []

    def test_optional_credential_id(self, ev_store):
        eid = ev_store.save("aws/enum_iam", "{}", credential_id=None)
        rows = ev_store.list()
        assert rows[0]["credential_id"] is None

    def test_log_api_call_returns_integer_id(self, ev_store):
        lid = ev_store.log_api_call(provider="aws", action="ListBuckets")
        assert isinstance(lid, int) and lid >= 1

    def test_log_api_all_optional_fields(self, ev_store):
        lid = ev_store.log_api_call(
            provider="azure", action="VMs.List",
            service="compute", request_params='{"rg": "prod"}',
            response_status=200, response_summary="3 VMs",
            technique_id="az/enum_vm", duration_ms=142,
        )
        assert lid >= 1

    def test_sequential_logs_unique_ids(self, ev_store):
        id1 = ev_store.log_api_call(provider="aws", action="ListBuckets")
        id2 = ev_store.log_api_call(provider="aws", action="ListRoles")
        assert id1 != id2


# ================================================================
# FindingStore — ORM path
# ================================================================

class TestFindingStoreORM:
    def test_add_returns_integer_id(self, fi_store):
        fid = fi_store.add(
            technique_id="aws/check_admin", tactic="privilege_escalation",
            title="AdminAccess found", severity="critical",
            provider="aws", description="...", evidence="{}",
        )
        assert isinstance(fid, int) and fid >= 1

    def test_list_empty(self, fi_store):
        assert fi_store.list() == []

    def test_duplicate_is_ignored(self, fi_store):
        kwargs = dict(
            technique_id="aws/check_admin", tactic="pe", title="Admin",
            severity="critical", provider="aws", description="d", evidence="{}",
        )
        id1 = fi_store.add(**kwargs)
        id2 = fi_store.add(**kwargs)
        assert id1 >= 1
        assert id2 == 0  # INSERT OR IGNORE behaviour
        assert len(fi_store.list()) == 1

    def test_severity_order_critical_first(self, fi_store):
        for sev, title in [("low", "Low"), ("critical", "Crit"), ("high", "High")]:
            fi_store.add(
                technique_id="t", tactic="tac", title=title,
                severity=sev, provider="aws", description="d", evidence="{}",
            )
        titles = [r["title"] for r in fi_store.list()]
        assert titles[0] == "Crit"
        assert titles[1] == "High"
        assert titles[2] == "Low"

    def test_optional_mitre_id(self, fi_store):
        fi_store.add(
            technique_id="t2", tactic="tac", title="No MITRE",
            severity="info", provider="aws", description="d", evidence="{}",
            mitre_id=None,
        )
        assert fi_store.list()[0]["mitre_id"] is None


# ================================================================
# AssetStore — ORM path
# ================================================================

class TestAssetStoreORM:
    def test_upsert_compute_creates_row(self, as_store):
        as_store.upsert_compute_instance(
            provider="aws", instance_id="i-abc123",
            name="web-01", state="running",
        )
        rows = as_store.list_compute_instances()
        assert len(rows) == 1
        assert rows[0]["instance_id"] == "i-abc123"

    def test_upsert_compute_updates_existing(self, as_store):
        as_store.upsert_compute_instance(
            provider="aws", instance_id="i-abc123", state="running"
        )
        as_store.upsert_compute_instance(
            provider="aws", instance_id="i-abc123", state="stopped"
        )
        rows = as_store.list_compute_instances()
        assert len(rows) == 1
        assert rows[0]["state"] == "stopped"

    def test_first_seen_preserved_on_update(self, as_store):
        as_store.upsert_compute_instance(
            provider="aws", instance_id="i-abc123", state="running"
        )
        first_seen = as_store.list_compute_instances()[0]["first_seen"]
        as_store.upsert_compute_instance(
            provider="aws", instance_id="i-abc123", state="stopped"
        )
        assert as_store.list_compute_instances()[0]["first_seen"] == first_seen

    def test_upsert_network_creates_row(self, as_store):
        as_store.upsert_network_asset(
            provider="aws", asset_type="vpc", asset_id="vpc-123"
        )
        rows = as_store.list_compute_instances()  # separate table
        assert rows == []  # no compute rows
        # verify network row via sqlite directly
        db_rows = as_store._db.fetchall("SELECT * FROM network_assets WHERE asset_id = 'vpc-123'")
        assert len(db_rows) == 1

    def test_filter_compute_by_provider(self, as_store):
        as_store.upsert_compute_instance(provider="aws", instance_id="i-1")
        as_store.upsert_compute_instance(provider="gcp", instance_id="vm-1")
        aws_rows = as_store.list_compute_instances(provider="aws")
        assert len(aws_rows) == 1
        assert aws_rows[0]["provider"] == "aws"

    def test_empty_list_on_empty_store(self, as_store):
        assert as_store.list_compute_instances() == []


# ================================================================
# AgentStore — ORM path
# ================================================================

class TestAgentStoreORM:
    def test_register_upserts(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        stored = ag_store.get(ag.id)
        assert stored is not None
        assert stored.id == ag.id

    def test_get_missing_returns_none(self, ag_store):
        assert ag_store.get("not-a-real-id") is None

    def test_heartbeat_updates_latency(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        ag_store.heartbeat(ag.id, latency_ms=42)
        assert ag_store.get(ag.id).latency_ms == 42

    def test_deregister_sets_inactive(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        ag_store.deregister(ag.id)
        assert ag_store.get(ag.id).status == "inactive"

    def test_revoke_sets_revoked(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        ag_store.revoke(ag.id)
        assert ag_store.get(ag.id).status == "revoked"

    def test_queue_and_pop_tasks(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        tid = ag_store.queue_task(ag.id, "shell", args=b"whoami")
        tasks = ag_store.pop_tasks(ag.id)
        assert len(tasks) == 1
        assert tasks[0].id == tid
        assert tasks[0].status == "running"

    def test_pop_tasks_marks_running(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        ag_store.queue_task(ag.id, "shell")
        ag_store.pop_tasks(ag.id)
        # Second pop should return nothing (already running)
        assert ag_store.pop_tasks(ag.id) == []

    def test_process_task_response_completes(self, ag_store):
        ag = _agent()
        ag_store.register(ag)
        tid = ag_store.queue_task(ag.id, "shell")
        ag_store.pop_tasks(ag.id)
        ag_store.process_task_response(tid, success=True, output=b"root", error=None)

    def test_callbacks_called_on_register(self, ag_store):
        events = []
        ag_store.on_update(lambda a: events.append(a.id))
        ag = _agent()
        ag_store.register(ag)
        assert ag.id in events

    def test_multi_agent_task_isolation(self, ag_store):
        ag1, ag2 = _agent(), _agent()
        ag_store.register(ag1)
        ag_store.register(ag2)
        ag_store.queue_task(ag1.id, "cmd-for-1")
        tasks_2 = ag_store.pop_tasks(ag2.id)
        assert tasks_2 == []
        tasks_1 = ag_store.pop_tasks(ag1.id)
        assert len(tasks_1) == 1
