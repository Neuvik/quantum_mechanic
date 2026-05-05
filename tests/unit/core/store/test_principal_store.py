# ================================================================
# TESTS: quantum_mechanic.core.store.principals
# ----------------------------------------------------------------
# WHAT:   Isolated tests for PrincipalStore SQL operations.
#         Tests the store directly against a real SQLite database.
#
# WHY:    Validates that principal CRUD extracted from workspace.py
#         works identically to the original inline SQL.
# ================================================================

import pytest

from quantum_mechanic.core.store.principals import PrincipalStore
from quantum_mechanic.core.store.models import Principal


@pytest.fixture
def store(workspace_db, workspace_id):
    return PrincipalStore(workspace_db, workspace_id)


# ================================================================
# add
# ================================================================

class TestPrincipalStoreAdd:
    def test_add_and_retrieve(self, store, workspace_db):
        # Insert parent account first (FK constraint)
        workspace_db.execute(
            "INSERT OR IGNORE INTO accounts (id, provider, name, account_type) VALUES (?, ?, ?, ?)",
            ("123456789012", "aws", "test-acct", "standalone"),
        )
        workspace_db.commit()

        principal = Principal(
            id="arn:aws:iam::123:user/alice", provider="aws",
            account_id="123456789012", principal_type="IAMUser",
            friendly_name="alice",
        )
        store.add(principal)
        result = store.get("aws", "arn:aws:iam::123:user/alice")
        assert result is not None
        assert result.id == "arn:aws:iam::123:user/alice"
        assert result.provider == "aws"
        assert result.friendly_name == "alice"
        assert result.principal_type == "IAMUser"

    def test_add_upserts_on_conflict(self, store):
        """Adding a principal with the same ID should update, not duplicate."""
        store.add(Principal(
            id="user-1", provider="aws", account_id=None,
            principal_type="IAMUser", friendly_name="old-name",
        ))
        store.add(Principal(
            id="user-1", provider="aws", account_id=None,
            principal_type="IAMUser", friendly_name="new-name",
        ))
        result = store.get("aws", "user-1")
        assert result.friendly_name == "new-name"

    def test_add_admin_equivalent(self, store, workspace_db):
        # Insert parent account first (FK constraint)
        workspace_db.execute(
            "INSERT OR IGNORE INTO accounts (id, provider, name, account_type) VALUES (?, ?, ?, ?)",
            ("123", "aws", "test-acct", "standalone"),
        )
        workspace_db.commit()

        store.add(Principal(
            id="admin-role", provider="aws", account_id="123",
            principal_type="IAMRole", friendly_name="admin",
            is_admin_equivalent=True,
        ))
        result = store.get("aws", "admin-role")
        assert result.is_admin_equivalent is True

    def test_add_with_raw_data(self, store):
        store.add(Principal(
            id="raw-user", provider="gcp", account_id=None,
            principal_type="ServiceAccount", friendly_name="sa",
            raw_data='{"email": "sa@project.iam.gserviceaccount.com"}',
        ))
        result = store.get("gcp", "raw-user")
        assert result.raw_data == '{"email": "sa@project.iam.gserviceaccount.com"}'


# ================================================================
# get
# ================================================================

class TestPrincipalStoreGet:
    def test_get_missing_returns_none(self, store):
        assert store.get("aws", "nonexistent") is None

    def test_get_returns_correct_type(self, store):
        store.add(Principal(
            id="typed", provider="azure", account_id=None,
            principal_type="ServicePrincipal", friendly_name="sp-1",
        ))
        result = store.get("azure", "typed")
        assert isinstance(result, Principal)

    def test_get_scoped_by_provider(self, store):
        """Same ID under different providers should not collide."""
        store.add(Principal(
            id="shared-id", provider="aws", account_id=None,
            principal_type="IAMUser", friendly_name="aws-user",
        ))
        store.add(Principal(
            id="shared-id", provider="gcp", account_id=None,
            principal_type="ServiceAccount", friendly_name="gcp-sa",
        ))
        aws_result = store.get("aws", "shared-id")
        gcp_result = store.get("gcp", "shared-id")
        assert aws_result.friendly_name == "aws-user"
        assert gcp_result.friendly_name == "gcp-sa"


# ================================================================
# list
# ================================================================

class TestPrincipalStoreList:
    def test_list_empty(self, store):
        assert store.list() == []

    def test_list_returns_all(self, store):
        store.add(Principal(id="p1", provider="aws", account_id=None, principal_type="IAMUser", friendly_name="a"))
        store.add(Principal(id="p2", provider="azure", account_id=None, principal_type="SP", friendly_name="b"))
        results = store.list()
        assert len(results) == 2

    def test_list_filter_by_provider(self, store):
        store.add(Principal(id="p1", provider="aws", account_id=None, principal_type="IAMUser", friendly_name="a"))
        store.add(Principal(id="p2", provider="azure", account_id=None, principal_type="SP", friendly_name="b"))
        store.add(Principal(id="p3", provider="aws", account_id=None, principal_type="IAMRole", friendly_name="c"))
        results = store.list(provider="aws")
        assert len(results) == 2
        assert all(r.provider == "aws" for r in results)
