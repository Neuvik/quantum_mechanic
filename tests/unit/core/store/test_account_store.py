# ================================================================
# TESTS: quantum_mechanic.core.store.accounts
# ----------------------------------------------------------------
# WHAT:   Isolated tests for AccountStore SQL operations.
#         Tests the store directly against a real SQLite database.
#
# WHY:    Validates that account CRUD extracted from workspace.py
#         works identically to the original inline SQL.
# ================================================================

import pytest

from quantum_mechanic.core.store.accounts import AccountStore
from quantum_mechanic.core.store.models import Account


@pytest.fixture
def store(workspace_db, workspace_id):
    return AccountStore(workspace_db, workspace_id)


# ================================================================
# add
# ================================================================

class TestAccountStoreAdd:
    def test_add_and_retrieve(self, store):
        account = Account(
            id="123456789012", provider="aws", name="prod-account",
            account_type="organization_member", parent_id=None, metadata=None,
        )
        store.add(account)
        result = store.get("123456789012")
        assert result is not None
        assert result.id == "123456789012"
        assert result.provider == "aws"
        assert result.name == "prod-account"
        assert result.account_type == "organization_member"

    def test_add_upserts_on_conflict(self, store):
        """Adding an account with the same ID should update, not duplicate."""
        store.add(Account(id="acct-1", provider="aws", name="old-name", account_type="standalone"))
        store.add(Account(id="acct-1", provider="aws", name="new-name", account_type="standalone"))
        result = store.get("acct-1")
        assert result.name == "new-name"

    def test_add_with_parent_id(self, store):
        store.add(Account(id="org-root", provider="aws", name="root", account_type="organization"))
        store.add(Account(
            id="child-1", provider="aws", name="dev",
            account_type="organization_member", parent_id="org-root",
        ))
        child = store.get("child-1")
        assert child.parent_id == "org-root"

    def test_add_with_metadata(self, store):
        store.add(Account(
            id="acct-meta", provider="azure", name="sub-1",
            account_type="subscription", metadata='{"tenant": "t-123"}',
        ))
        result = store.get("acct-meta")
        assert result.metadata == '{"tenant": "t-123"}'


# ================================================================
# get
# ================================================================

class TestAccountStoreGet:
    def test_get_missing_returns_none(self, store):
        assert store.get("nonexistent") is None

    def test_get_returns_correct_type(self, store):
        store.add(Account(id="typed", provider="gcp", name="project-1", account_type="project"))
        result = store.get("typed")
        assert isinstance(result, Account)


# ================================================================
# list
# ================================================================

class TestAccountStoreList:
    def test_list_empty(self, store):
        assert store.list() == []

    def test_list_returns_all(self, store):
        store.add(Account(id="a1", provider="aws", name="acct-a", account_type="standalone"))
        store.add(Account(id="a2", provider="azure", name="sub-b", account_type="subscription"))
        results = store.list()
        assert len(results) == 2

    def test_list_filter_by_provider(self, store):
        store.add(Account(id="a1", provider="aws", name="acct-a", account_type="standalone"))
        store.add(Account(id="a2", provider="azure", name="sub-b", account_type="subscription"))
        store.add(Account(id="a3", provider="aws", name="acct-c", account_type="standalone"))
        results = store.list(provider="aws")
        assert len(results) == 2
        assert all(r.provider == "aws" for r in results)
