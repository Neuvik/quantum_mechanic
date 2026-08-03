# ================================================================
# TESTS: CredentialStore — SQLAlchemy (ORM) path
# ----------------------------------------------------------------
# WHAT:   Tests the CredentialStore against the SQLAlchemy backend.
#         Exercises the same operations as test_credential_store.py
#         but with QM_DATABASE_URL set to a sqlite:// URL, which
#         forces the ORM code path instead of the raw sqlite3 path.
#
# WHY:    The ORM path must pass the same invariants as the sqlite3
#         path. This file is the "second dialect" of the store tests.
# ================================================================

import json
import os

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.credentials import CredentialStore


@pytest.fixture
def orm_store(tmp_path):
    """CredentialStore on the SQLAlchemy path.

    Sets QM_DATABASE_URL to a file-based SQLite URL so the ORM path
    is activated. The database is pre-migrated via Database.create so
    all tables exist and the workspace FK is satisfied.
    """
    db = Database.create("orm-test", tmp_path)
    url = f"sqlite:///{db.db_path}"

    # Activate the ORM path for this test
    with pytest.MonkeyPatch().context() as mp:
        mp.setenv("QM_DATABASE_URL", url)
        store = CredentialStore(db, _get_workspace_id(db))
        yield store

    db.close()


def _get_workspace_id(db: Database) -> str:
    row = db.fetchone("SELECT id FROM workspace WHERE name = 'orm-test'")
    return row["id"]


# ================================================================
# add — ORM path
# ================================================================

class TestCredentialStoreORMAdd:
    def test_returns_integer_id(self, orm_store):
        cred_id = orm_store.add(
            provider="aws",
            credential_type="access_key",
            secret_data='{"key": "AKIA"}',
        )
        assert isinstance(cred_id, int)
        assert cred_id >= 1

    def test_sequential_ids_are_unique(self, orm_store):
        id1 = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        id2 = orm_store.add(provider="azure", credential_type="sp", secret_data="{}")
        assert id1 != id2

    def test_optional_fields_default_to_none(self, orm_store):
        cred_id = orm_store.add(provider="gcp", credential_type="sa_key", secret_data="{}")
        cred = orm_store.get(cred_id)
        assert cred.friendly_name is None
        assert cred.principal_id is None
        assert cred.expires_at is None
        assert cred.auto_refresh is False


# ================================================================
# get / secret isolation — ORM path
# ================================================================

class TestCredentialStoreORMGet:
    def test_get_existing_returns_credential(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        cred = orm_store.get(cred_id)
        assert cred is not None
        assert cred.id == cred_id
        assert cred.provider == "aws"

    def test_get_missing_returns_none(self, orm_store):
        assert orm_store.get(99999) is None

    def test_get_does_not_expose_secret(self, orm_store):
        cred_id = orm_store.add(
            provider="aws",
            credential_type="access_key",
            secret_data='{"secret": "TOP_SECRET"}',
        )
        cred = orm_store.get(cred_id)
        assert not hasattr(cred, "secret_data")

    def test_get_secret_returns_raw_secret(self, orm_store):
        payload = json.dumps({"secret_access_key": "s3cr3t"})
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data=payload)
        assert orm_store.get_secret(cred_id) == payload

    def test_get_secret_missing_returns_none(self, orm_store):
        assert orm_store.get_secret(99999) is None


# ================================================================
# list — ORM path
# ================================================================

class TestCredentialStoreORMList:
    def test_returns_all_when_no_filters(self, orm_store):
        orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.add(provider="azure", credential_type="sp", secret_data="{}")
        assert len(orm_store.list()) == 2

    def test_filter_by_provider(self, orm_store):
        orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.add(provider="gcp", credential_type="sa_key", secret_data="{}")
        results = orm_store.list(provider="gcp")
        assert len(results) == 1
        assert results[0].provider == "gcp"

    def test_filter_by_status(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.add(provider="azure", credential_type="sp", secret_data="{}")
        orm_store.update_status(cred_id, "expired")
        active = orm_store.list(status="active")
        assert len(active) == 1
        assert active[0].provider == "azure"

    def test_ordered_by_id(self, orm_store):
        for provider in ("aws", "gcp", "azure"):
            orm_store.add(provider=provider, credential_type="t", secret_data="{}")
        ids = [c.id for c in orm_store.list()]
        assert ids == sorted(ids)


# ================================================================
# update_status — ORM path
# ================================================================

class TestCredentialStoreORMUpdateStatus:
    def test_status_changes(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.update_status(cred_id, "expired")
        assert orm_store.get(cred_id).status == "expired"

    def test_multiple_transitions(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        for status in ("active", "expired", "revoked"):
            orm_store.update_status(cred_id, status)
            assert orm_store.get(cred_id).status == status


# ================================================================
# update_principal — ORM path
# ================================================================

class TestCredentialStoreORMUpdatePrincipal:
    def test_links_principal_id(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.update_principal(cred_id, "arn:aws:iam::123:user/alice")
        assert orm_store.get(cred_id).principal_id == "arn:aws:iam::123:user/alice"

    def test_updates_friendly_name_when_provided(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.update_principal(cred_id, "arn::user/bob", friendly_name="bob")
        assert orm_store.get(cred_id).friendly_name == "bob"


# ================================================================
# delete — ORM path
# ================================================================

class TestCredentialStoreORMDelete:
    def test_delete_existing_returns_true(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        assert orm_store.delete(cred_id) is True

    def test_deleted_credential_not_retrievable(self, orm_store):
        cred_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        orm_store.delete(cred_id)
        assert orm_store.get(cred_id) is None

    def test_delete_missing_returns_false(self, orm_store):
        assert orm_store.delete(99999) is False

    def test_delete_nulls_derived_from_fk(self, orm_store):
        parent_id = orm_store.add(provider="aws", credential_type="access_key", secret_data="{}")
        child_id = orm_store.add(
            provider="aws",
            credential_type="role_session",
            secret_data="{}",
            derived_from_id=parent_id,
        )
        orm_store.delete(parent_id)
        child = orm_store.get(child_id)
        assert child is not None
        assert child.derived_from_id is None
