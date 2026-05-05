# ================================================================
# TESTS: quantum_mechanic.core.store.credentials
# ----------------------------------------------------------------
# WHAT:   Isolated tests for CredentialStore SQL operations.
#         These test the store directly — not through Workspace —
#         so regressions in the delegation layer can't mask bugs.
#
# WHY:    CredentialStore owns the most FK-sensitive logic in QM:
#         delete cascades, secret isolation, and filter queries.
#         Each path needs its own test.
# ================================================================

import json

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.credentials import CredentialStore


@pytest.fixture
def db(workspace_db):
    return workspace_db


@pytest.fixture
def store(workspace_db, workspace_id):
    return CredentialStore(workspace_db, workspace_id)


# ================================================================
# add
# ================================================================

class TestCredentialStoreAdd:
    def test_returns_integer_id(self, store):
        cred_id = store.add(
            provider="aws",
            credential_type="access_key",
            secret_data='{"key": "AKIA"}',
        )
        assert isinstance(cred_id, int)
        assert cred_id >= 1

    def test_sequential_ids_are_unique(self, store):
        id1 = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        id2 = store.add(provider="azure", credential_type="sp", secret_data="{}")
        assert id1 != id2

    def test_optional_fields_default_to_none(self, store):
        cred_id = store.add(provider="gcp", credential_type="sa_key", secret_data="{}")
        cred = store.get(cred_id)
        assert cred.friendly_name is None
        assert cred.principal_id is None
        assert cred.account_id is None
        assert cred.expires_at is None
        assert cred.auto_refresh is False

    def test_all_fields_persisted(self, store):
        cred_id = store.add(
            provider="azure",
            credential_type="sp",
            secret_data='{"client_secret": "x"}',
            friendly_name="my-sp",
            obtained_via="manual",
            auto_refresh=True,
        )
        cred = store.get(cred_id)
        assert cred.provider == "azure"
        assert cred.credential_type == "sp"
        assert cred.friendly_name == "my-sp"
        assert cred.auto_refresh is True


# ================================================================
# get / secret isolation
# ================================================================

class TestCredentialStoreGet:
    def test_get_existing_returns_credential(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        cred = store.get(cred_id)
        assert cred is not None
        assert cred.id == cred_id
        assert cred.provider == "aws"

    def test_get_missing_returns_none(self, store):
        assert store.get(99999) is None

    def test_get_does_not_expose_secret(self, store):
        """get() must not leak secret_data — only get_secret() should."""
        cred_id = store.add(
            provider="aws",
            credential_type="access_key",
            secret_data='{"secret": "TOP_SECRET"}',
        )
        cred = store.get(cred_id)
        # Credential dataclass has no secret_data field
        assert not hasattr(cred, "secret_data")

    def test_get_secret_returns_raw_secret(self, store):
        payload = json.dumps({"secret_access_key": "s3cr3t"})
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data=payload)
        assert store.get_secret(cred_id) == payload

    def test_get_secret_missing_returns_none(self, store):
        assert store.get_secret(99999) is None


# ================================================================
# list
# ================================================================

class TestCredentialStoreList:
    def test_returns_all_when_no_filters(self, store):
        store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.add(provider="azure", credential_type="sp", secret_data="{}")
        assert len(store.list()) == 2

    def test_filter_by_provider(self, store):
        store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.add(provider="gcp", credential_type="sa_key", secret_data="{}")
        results = store.list(provider="gcp")
        assert len(results) == 1
        assert results[0].provider == "gcp"

    def test_filter_by_status(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.add(provider="azure", credential_type="sp", secret_data="{}")
        store.update_status(cred_id, "expired")
        active = store.list(status="active")
        assert len(active) == 1
        assert active[0].provider == "azure"

    def test_empty_list_on_empty_store(self, store):
        assert store.list() == []

    def test_ordered_by_id(self, store):
        for provider in ("aws", "gcp", "azure"):
            store.add(provider=provider, credential_type="t", secret_data="{}")
        ids = [c.id for c in store.list()]
        assert ids == sorted(ids)


# ================================================================
# update_status
# ================================================================

class TestCredentialStoreUpdateStatus:
    def test_status_changes(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.update_status(cred_id, "expired")
        cred = store.get(cred_id)
        assert cred.status == "expired"

    def test_multiple_status_transitions(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        for status in ("active", "expired", "revoked"):
            store.update_status(cred_id, status)
            assert store.get(cred_id).status == status


# ================================================================
# update_principal
# ================================================================

class TestCredentialStoreUpdatePrincipal:
    def test_links_principal_id(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.update_principal(cred_id, "arn:aws:iam::123:user/alice")
        cred = store.get(cred_id)
        assert cred.principal_id == "arn:aws:iam::123:user/alice"

    def test_updates_friendly_name_when_provided(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.update_principal(cred_id, "arn::user/bob", friendly_name="bob")
        cred = store.get(cred_id)
        assert cred.friendly_name == "bob"

    def test_friendly_name_optional(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}", friendly_name="original")
        store.update_principal(cred_id, "arn::user/alice")
        # friendly_name should be unchanged when not passed
        cred = store.get(cred_id)
        assert cred.friendly_name == "original"


# ================================================================
# delete
# ================================================================

class TestCredentialStoreDelete:
    def test_delete_existing_returns_true(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        assert store.delete(cred_id) is True

    def test_deleted_credential_not_retrievable(self, store):
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        store.delete(cred_id)
        assert store.get(cred_id) is None

    def test_delete_missing_returns_false(self, store):
        assert store.delete(99999) is False

    def test_delete_nulls_api_log_fk(self, store, db):
        """Deleting a credential must NULL api_log.credential_id (preserve audit trail)."""
        cred_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        db.execute(
            """INSERT INTO api_log
               (timestamp, credential_id, provider, action)
               VALUES ('2024-01-01T00:00:00', ?, 'aws', 'sts:GetCallerIdentity')""",
            (cred_id,),
        )
        db.commit()
        store.delete(cred_id)
        row = db.fetchone("SELECT credential_id FROM api_log WHERE action = 'sts:GetCallerIdentity'")
        assert row["credential_id"] is None

    def test_delete_nulls_derived_from_fk(self, store):
        """Children's derived_from_id is NULLed, not cascade-deleted."""
        parent_id = store.add(provider="aws", credential_type="access_key", secret_data="{}")
        child_id = store.add(
            provider="aws",
            credential_type="role_session",
            secret_data="{}",
            derived_from_id=parent_id,
        )
        store.delete(parent_id)
        child = store.get(child_id)
        assert child is not None          # child survives
        assert child.derived_from_id is None  # unlinked, not deleted
