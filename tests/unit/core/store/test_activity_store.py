"""Tests for ActivityStore + migration 008_activity_log.sql.

Guards a real release-blocker discovered during review: workspace.py at
v1.0-rc0 imported ActivityStore and called it on every Workspace.create()
/ .load(), but store/activity.py and migration 008 were never committed.
Anyone cloning from the tag hit an ImportError on the first workspace
operation. These tests exist so it can never happen silently again.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from quantum_mechanic.core.workspace import Workspace


@pytest.fixture
def workspace():
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-activity", workspace_dir=Path(td))
        yield ws
        ws.close()


def test_activity_store_is_reachable_from_workspace(workspace):
    """OUTCOME: The whole import + init chain works.

    ANTI-GAMIFICATION: This is the specific bug — if store/activity.py or
    migration 008 gets dropped again, this test fails immediately on the
    Workspace.create() import. Every workspace test in the tree implicitly
    depends on this working; making it explicit means the failure surfaces
    with a clear message instead of cascading through half the suite.
    """
    assert workspace._activity is not None


def test_add_activity_log_returns_row_id(workspace):
    row_id = workspace.add_activity_log(
        "discovery/whoami", "INFO", "starting whoami"
    )
    assert isinstance(row_id, int)
    assert row_id > 0


def test_list_activity_log_returns_recorded_entry(workspace):
    workspace.add_activity_log("discovery/whoami", "INFO", "starting")
    entries = workspace.list_activity_log(technique_id="discovery/whoami")
    assert len(entries) == 1
    assert entries[0]["message"] == "starting"
    assert entries[0]["level"] == "INFO"


def test_data_field_round_trips_as_json(workspace):
    """OUTCOME: The `data` column stores JSON — a dict in, a JSON-string out
    (or the loader turns it back into a dict, depending on the store)."""
    workspace.add_activity_log(
        "discovery/whoami", "ERROR",
        "HTTP failure",
        data={"http_status": 500, "url": "https://example.com"},
    )
    entries = workspace.list_activity_log()
    assert entries[0]["data"] is not None
    import json
    parsed = json.loads(entries[0]["data"])
    assert parsed["http_status"] == 500


def test_filter_by_level(workspace):
    workspace.add_activity_log("discovery/whoami", "INFO", "starting")
    workspace.add_activity_log("discovery/whoami", "ERROR", "boom")
    workspace.add_activity_log("discovery/whoami", "SUCCESS", "done")

    errors = workspace.list_activity_log(level="ERROR")
    assert len(errors) == 1
    assert errors[0]["message"] == "boom"


def test_filter_by_technique(workspace):
    workspace.add_activity_log("discovery/whoami", "INFO", "A")
    workspace.add_activity_log("discovery/enum_iam", "INFO", "B")

    hits = workspace.list_activity_log(technique_id="discovery/enum_iam")
    assert len(hits) == 1
    assert hits[0]["message"] == "B"


def test_list_orders_newest_first(workspace):
    """OUTCOME: list_activity_log returns entries in DESC timestamp order
    so the newest event is at index 0 (matches operator expectation for
    'what just happened')."""
    workspace.add_activity_log("discovery/whoami", "INFO", "first")
    workspace.add_activity_log("discovery/whoami", "INFO", "second")
    workspace.add_activity_log("discovery/whoami", "INFO", "third")

    entries = workspace.list_activity_log()
    messages = [e["message"] for e in entries]
    assert messages == ["third", "second", "first"]


def test_limit_caps_returned_rows(workspace):
    for i in range(10):
        workspace.add_activity_log("discovery/whoami", "INFO", f"n={i}")
    entries = workspace.list_activity_log(limit=3)
    assert len(entries) == 3


def test_migration_008_creates_activity_log_table(workspace):
    """OUTCOME: The 008 migration ran during Workspace.create() and the
    activity_log table + indices exist."""
    # Direct DB query — bypass the store to verify the schema is really there.
    row = workspace.db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='activity_log'"
    )
    assert row is not None

    # Indices too.
    idx_rows = workspace.db.fetchall(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='activity_log'"
    )
    idx_names = {r["name"] for r in idx_rows}
    assert "idx_activity_workspace" in idx_names
    assert "idx_activity_technique" in idx_names
    assert "idx_activity_level" in idx_names
