# ================================================================
# TESTS: quantum_mechanic.core.workspace
# ----------------------------------------------------------------
# WHAT:   Tests the workspace domain layer — credential CRUD,
#         principal storage, account management, and API logging.
#
# WHY:    Every technique pipes data through the workspace.
#         If credential storage or principal linking is broken,
#         the entire attack chain falls apart.
# ================================================================

import json

import pytest

from quantum_mechanic.core.workspace import (
    Account,
    Principal,
    Workspace,
)


@pytest.fixture
def workspace(tmp_path):
    """Create a fresh workspace for each test."""
    ws = Workspace.create("test-engagement", tmp_path)
    yield ws
    ws.close()


class TestWorkspaceCredentials:
    """Test credential CRUD operations."""

    def test_add_credential(self, workspace):
        """Adding a credential returns an auto-incremented ID."""
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "sa_key1"}),
            friendly_name="profile:sa_key1",
            obtained_via="manual import",
        )
        assert cred_id == 1

    def test_add_credential_all_fields(self, workspace):
        """Adding a credential with all optional parameters stores them properly."""
        workspace.db.execute("INSERT INTO accounts (id, provider) VALUES ('acc1', 'gcp')")
        workspace.db.commit()
        
        cred_id = workspace.add_credential(
            provider="gcp",
            credential_type="service_account",
            secret_data="{}",
            friendly_name="sa-full",
            principal_id="user1",
            account_id="acc1",
            derived_from_id=None,
            expires_at="2030-01-01T00:00:00Z",
            auto_refresh=True,
            obtained_via="injected",
            raw_data='{"raw": "yes"}',
        )
        assert cred_id == 1
        cred = workspace.get_credential(cred_id)
        assert cred.provider == "gcp"
        assert cred.credential_type == "service_account"
        assert cred.friendly_name == "sa-full"
        assert cred.principal_id == "user1"
        assert cred.account_id == "acc1"
        assert cred.expires_at == "2030-01-01T00:00:00Z"
        assert cred.auto_refresh is True
        assert cred.obtained_via == "injected"
        assert cred.raw_data == '{"raw": "yes"}'

    def test_get_credential(self, workspace):
        """Retrieving a credential returns all fields except secret_data."""
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "test"}),
            friendly_name="test-cred",
        )
        cred = workspace.get_credential(cred_id)
        assert cred is not None
        assert cred.provider == "aws"
        assert cred.credential_type == "access_key"
        assert cred.friendly_name == "test-cred"
        assert cred.status == "active"

    def test_get_credential_missing(self, workspace):
        """Retrieving a nonexistent credential returns None."""
        assert workspace.get_credential(999) is None

    def test_get_credential_secret(self, workspace):
        """Secret data is stored and retrievable separately."""
        secret = json.dumps({"access_key_id": "AKIAEXAMPLE"})
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=secret,
        )
        retrieved = workspace.get_credential_secret(cred_id)
        assert retrieved == secret

    def test_list_credentials_empty(self, workspace):
        """Listing with no credentials returns empty list."""
        assert workspace.list_credentials() == []

    def test_list_credentials_with_filter(self, workspace):
        """Listing with provider filter returns only matching creds."""
        workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
        )
        workspace.add_credential(
            provider="azure",
            credential_type="refresh_token",
            secret_data="{}",
        )
        aws_creds = workspace.list_credentials(provider="aws")
        assert len(aws_creds) == 1
        assert aws_creds[0].provider == "aws"

    def test_update_credential_status(self, workspace):
        """Status updates are persisted."""
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
        )
        workspace.update_credential_status(cred_id, "expired")
        cred = workspace.get_credential(cred_id)
        assert cred.status == "expired"

    def test_update_credential_principal(self, workspace):
        """Linking a credential to a principal updates both fields."""
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
        )
        workspace.update_credential_principal(cred_id, "arn:aws:iam::123456:user/admin", "admin")
        cred = workspace.get_credential(cred_id)
        assert cred.principal_id == "arn:aws:iam::123456:user/admin"
        assert cred.friendly_name == "admin"

    def test_credential_provenance_chain(self, workspace):
        """derived_from_id tracks credential provenance."""
        parent_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
            friendly_name="parent",
        )
        child_id = workspace.add_credential(
            provider="aws",
            credential_type="assumed_role",
            secret_data="{}",
            friendly_name="child",
            derived_from_id=parent_id,
            obtained_via=f"assumed from cred #{parent_id}",
        )
        child = workspace.get_credential(child_id)
        assert child.derived_from_id == parent_id
        assert "assumed from" in child.obtained_via

    def test_active_credential_setter(self, workspace):
        """Setting active credential validates the ID exists."""
        cred_id = workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
        )
        workspace.active_credential_id = cred_id
        assert workspace.active_credential_id == cred_id

    def test_active_credential_invalid_raises(self, workspace):
        """Setting active credential to nonexistent ID raises."""
        with pytest.raises(ValueError):
            workspace.active_credential_id = 999


class TestWorkspacePrincipals:
    """Test principal storage operations."""

    def test_add_and_get_principal(self, workspace):
        """Storing and retrieving a principal preserves all fields."""
        principal = Principal(
            id="arn:aws:iam::123456:user/admin",
            provider="aws",
            account_id=None,
            principal_type="user",
            friendly_name="admin",
            is_admin_equivalent=True,
            raw_data='{"UserId": "AIDAEXAMPLE"}',
        )
        workspace.add_principal(principal)

        retrieved = workspace.get_principal("aws", "arn:aws:iam::123456:user/admin")
        assert retrieved is not None
        assert retrieved.friendly_name == "admin"
        assert retrieved.principal_type == "user"
        assert retrieved.is_admin_equivalent is True

    def test_get_principal_missing(self, workspace):
        """Retrieving a nonexistent principal returns None."""
        assert workspace.get_principal("aws", "nonexistent") is None

    def test_upsert_principal(self, workspace):
        """Adding a principal with same PK updates it (INSERT OR REPLACE)."""
        p1 = Principal(
            id="arn:aws:iam::123:user/test",
            provider="aws",
            account_id=None,
            principal_type="user",
            friendly_name="old-name",
        )
        workspace.add_principal(p1)

        p2 = Principal(
            id="arn:aws:iam::123:user/test",
            provider="aws",
            account_id=None,
            principal_type="user",
            friendly_name="new-name",
        )
        workspace.add_principal(p2)

        retrieved = workspace.get_principal("aws", "arn:aws:iam::123:user/test")
        assert retrieved.friendly_name == "new-name"


class TestWorkspaceAccounts:
    """Test account management."""

    def test_add_and_get_account(self, workspace):
        """Storing and retrieving an account preserves all fields."""
        account = Account(
            id="123456789012",
            provider="aws",
            name="acme-prod",
            account_type="account",
        )
        workspace.add_account(account)

        retrieved = workspace.get_account("123456789012")
        assert retrieved is not None
        assert retrieved.name == "acme-prod"
        assert retrieved.provider == "aws"

    def test_get_account_missing(self, workspace):
        """Retrieving a nonexistent account returns None."""
        assert workspace.get_account("nonexistent") is None


class TestWorkspaceApiLog:
    """Test API call logging."""

    def test_log_api_call(self, workspace):
        """Logging an API call returns an ID and persists the entry."""
        log_id = workspace.log_api_call(
            provider="aws",
            action="GetCallerIdentity",
            service="sts",
            response_status=200,
            response_summary="user/admin",
            duration_ms=150,
        )
        assert log_id >= 1

        row = workspace.db.fetchone("SELECT * FROM api_log WHERE id = ?", (log_id,))
        assert row["action"] == "GetCallerIdentity"
        assert row["provider"] == "aws"
        assert row["duration_ms"] == 150

    def test_log_multiple_calls(self, workspace):
        """Multiple API calls are recorded in order."""
        workspace.log_api_call(provider="aws", action="Call1")
        workspace.log_api_call(provider="aws", action="Call2")
        workspace.log_api_call(provider="azure", action="Call3")

        rows = workspace.db.fetchall("SELECT action FROM api_log ORDER BY id")
        assert [r["action"] for r in rows] == ["Call1", "Call2", "Call3"]


class TestWorkspaceLifecycle:
    """Test workspace creation, listing, and loading."""

    def test_create_and_load(self, tmp_path):
        """A workspace can be created and then loaded by name."""
        ws1 = Workspace.create("lifecycle-test", tmp_path)
        ws1.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
        )
        ws1.close()

        ws2 = Workspace.load("lifecycle-test", tmp_path)
        creds = ws2.list_credentials()
        assert len(creds) == 1
        ws2.close()

    def test_list_all(self, tmp_path):
        """list_all returns all workspaces."""
        for name in ["alpha", "beta"]:
            ws = Workspace.create(name, tmp_path)
            ws.close()

        all_ws = Workspace.list_all(tmp_path)
        names = [w["name"] for w in all_ws]
        assert "alpha" in names
        assert "beta" in names
