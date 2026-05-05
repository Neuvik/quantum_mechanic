# ================================================================
# conftest.py — shared fixtures for store unit tests
# ================================================================
# The Database.create() factory applies all migrations AND writes
# the workspace row (with auto-generated UUID) via _init_workspace.
# All store fixtures reference the actual workspace UUID fetched
# from the workspace table — matching how AgentStore + EvidenceStore
# scope their queries in production.
# ================================================================

import pytest

from quantum_mechanic.core.database import Database


@pytest.fixture
def workspace_db(tmp_path):
    """Fresh Database with full schema and a seeded workspace row."""
    db = Database.create("store-test", tmp_path)
    yield db
    db.close()


@pytest.fixture
def workspace_id(workspace_db):
    """The UUID assigned by _init_workspace for the store-test workspace."""
    row = workspace_db.fetchone("SELECT id FROM workspace WHERE name = 'store-test'")
    return row["id"]
