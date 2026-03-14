# ================================================================
# TESTS: quantum_mechanic.core.context
# ----------------------------------------------------------------
# WHAT:   Tests ExecutionContext — the ctx object passed to every
#         technique. Focuses on: API call counting, principal/account
#         storage in the workspace, and the whoami() interaction.
#
# WHY:    context.py is the bridge between a technique and the
#         workspace DB. If attribute delegation or call-counting
#         breaks, evidence is silently lost.
#
# ANTI-GAMIFICATION: We mock only at the AuthProvider boundary
#   and verify workspace state changes (DB rows), not just mock call counts.
# ================================================================

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import WhoAmIResult


# ================================================================
# Fixtures
# ================================================================

@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    ws = Workspace.create("ctx-test", tmp_path)
    yield ws
    ws.close()


def _make_result(
    provider="aws",
    principal_id="arn:aws:iam::123456:user/admin",
    principal_type="user",
    friendly_name="admin",
    account_id="123456",
    account_name="acme-prod",
) -> WhoAmIResult:
    return WhoAmIResult(
        provider=provider,
        principal_id=principal_id,
        principal_type=principal_type,
        friendly_name=friendly_name,
        account_id=account_id,
        account_name=account_name,
    )


def _make_provider(result: WhoAmIResult) -> MagicMock:
    """Build a mock AuthProvider that returns the given WhoAmIResult."""
    p = MagicMock()
    p.provider_name = result.provider
    p.whoami.return_value = result
    return p


def _make_ctx(workspace: Workspace, result: WhoAmIResult, **kwargs) -> ExecutionContext:
    cred_id = workspace.add_credential(
        provider=result.provider,
        credential_type="access_key",
        secret_data="{}",
    )
    provider = _make_provider(result)
    return ExecutionContext(
        workspace=workspace,
        credential_id=cred_id,
        provider=provider,
        session=object(),
        technique_id=kwargs.get("technique_id", "discovery/whoami"),
        safe_mode=kwargs.get("safe_mode", False),
        params=kwargs.get("params"),
    )


# ================================================================
# Properties
# ================================================================

class TestExecutionContextProperties:
    def test_provider_name_matches_provider(self, workspace):
        ctx = _make_ctx(workspace, _make_result(provider="azure"))
        assert ctx.provider_name == "azure"

    def test_api_call_count_starts_at_zero(self, workspace):
        ctx = _make_ctx(workspace, _make_result())
        assert ctx.api_call_count == 0

    def test_safe_mode_propagated(self, workspace):
        ctx = _make_ctx(workspace, _make_result(), safe_mode=True)
        assert ctx.safe_mode is True

    def test_params_defaults_to_empty_dict(self, workspace):
        ctx = _make_ctx(workspace, _make_result(), params=None)
        assert ctx.params == {}

    def test_params_stored(self, workspace):
        ctx = _make_ctx(workspace, _make_result(), params={"region": "us-east-1"})
        assert ctx.params["region"] == "us-east-1"


# ================================================================
# whoami()
# ================================================================

class TestExecutionContextWhoami:
    def test_whoami_returns_who_am_i_result(self, workspace):
        """whoami() returns the WhoAmIResult from the provider."""
        result = _make_result()
        ctx = _make_ctx(workspace, result)
        returned = ctx.whoami()
        assert returned.friendly_name == "admin"
        assert returned.principal_id == "arn:aws:iam::123456:user/admin"

    def test_whoami_increments_api_call_count(self, workspace):
        """Each whoami() call increments the API call counter."""
        ctx = _make_ctx(workspace, _make_result())
        assert ctx.api_call_count == 0
        ctx.whoami()
        assert ctx.api_call_count == 1
        ctx.whoami()
        assert ctx.api_call_count == 2

    def test_whoami_logs_api_call_in_workspace(self, workspace):
        """whoami() writes an entry to the workspace api_log table."""
        ctx = _make_ctx(workspace, _make_result())
        ctx.whoami()
        rows = workspace.db.fetchall("SELECT * FROM api_log")
        assert len(rows) == 1
        assert rows[0]["action"] == "whoami"
        assert rows[0]["provider"] == "aws"

    def test_whoami_stores_principal_in_workspace(self, workspace):
        """whoami() persists the principal to the workspace DB."""
        result = _make_result(principal_id="arn:aws:iam::123:user/bob", friendly_name="bob")
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        principal = workspace.get_principal("aws", "arn:aws:iam::123:user/bob")
        assert principal is not None
        assert principal.friendly_name == "bob"

    def test_whoami_stores_account_in_workspace(self, workspace):
        """whoami() persists the account to the workspace DB."""
        result = _make_result(account_id="999888", account_name="acme-dev")
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        account = workspace.get_account("999888")
        assert account is not None
        assert account.provider == "aws"

    def test_whoami_links_credential_to_principal(self, workspace):
        """whoami() calls update_credential_principal on the workspace."""
        result = _make_result(principal_id="arn:aws:iam::123:user/admin", friendly_name="admin")
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        cred = workspace.get_credential(ctx.credential_id)
        assert cred is not None
        assert cred.principal_id == "arn:aws:iam::123:user/admin"
        assert cred.friendly_name == "admin"

    def test_whoami_api_log_records_technique_id(self, workspace):
        """The api_log entry for whoami() includes the technique_id."""
        result = _make_result()
        ctx = _make_ctx(workspace, result, technique_id="discovery/whoami")
        ctx.whoami()
        row = workspace.db.fetchone("SELECT technique_id FROM api_log LIMIT 1")
        assert row["technique_id"] == "discovery/whoami"

    def test_whoami_calls_provider_whoami(self, workspace):
        """whoami() calls provider.whoami() exactly once per call."""
        result = _make_result()
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        ctx.provider.whoami.assert_called_once()

    def test_whoami_azure_logs_identity_service(self, workspace):
        """Azure whoami() logs service='identity' not 'sts'."""
        result = _make_result(
            provider="azure",
            principal_id="azure-oid-001",
            account_id="sub-123",
            account_name="my-subscription",
        )
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        row = workspace.db.fetchone("SELECT service FROM api_log LIMIT 1")
        assert row["service"] == "identity"

    def test_whoami_aws_logs_sts_service(self, workspace):
        """AWS whoami() logs service='sts'."""
        result = _make_result(provider="aws")
        ctx = _make_ctx(workspace, result)
        ctx.whoami()
        row = workspace.db.fetchone("SELECT service FROM api_log LIMIT 1")
        assert row["service"] == "sts"


# ================================================================
# log()
# ================================================================

class TestExecutionContextLog:
    def test_log_does_not_raise(self, workspace):
        """ctx.log() is callable without raising."""
        ctx = _make_ctx(workspace, _make_result(), technique_id="discovery/whoami")
        ctx.log("This is a test log message.")  # should not raise

    def test_log_with_no_technique_id(self, workspace):
        """ctx.log() works even when technique_id is None."""
        result = _make_result()
        cred_id = workspace.add_credential(
            provider=result.provider, credential_type="access_key", secret_data="{}"
        )
        ctx = ExecutionContext(
            workspace=workspace,
            credential_id=cred_id,
            provider=_make_provider(result),
            session=object(),
            technique_id=None,
        )
        ctx.log("no technique id test")  # should not raise
