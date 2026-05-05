# ================================================================
# TESTS: quantum_mechanic.core.workspace — credential deletion
# ----------------------------------------------------------------
# WHAT:   Tests that deleting a credential works even when the
#         credential has linked records (api_log entries,
#         principal references).
#
# WHY:    Credentials #2 and #3 failed to delete with a
#         FOREIGN KEY constraint error because api_log rows
#         referenced them. The delete must handle linked data
#         gracefully — null out FK references in api_log but
#         preserve the audit trail.
# ================================================================

import json

import pytest

from quantum_mechanic.core.workspace import Workspace


@pytest.fixture
def workspace_with_linked_data(tmp_path):
    """Create a workspace with a credential that has linked api_log entries.

    This reproduces the exact scenario: import a cred, run whoami
    (which logs API calls), then try to delete the cred.
    """
    ws = Workspace.create("delete-test", tmp_path)

    # --------------------------------------------------------
    # Add a credential and log API calls against it.
    # This simulates what happens when you run discovery/whoami.
    # --------------------------------------------------------
    cred_id = ws.add_credential(
        provider="aws",
        credential_type="access_key",
        secret_data=json.dumps({"profile_name": "test"}),
        friendly_name="profile:test",
    )
    ws.log_api_call(
        provider="aws",
        action="GetCallerIdentity",
        credential_id=cred_id,
        service="sts",
        response_status=200,
        response_summary="user/admin",
        technique_id="discovery/whoami",
        duration_ms=150,
    )
    ws.log_api_call(
        provider="aws",
        action="GetCallerIdentity",
        credential_id=cred_id,
        service="sts",
        response_status=200,
        technique_id="discovery/whoami",
        duration_ms=120,
    )

    yield ws, cred_id
    ws.close()


class TestCredentialDeleteWithLinkedData:
    """Test deleting credentials that have FK references."""

    def test_delete_with_api_log_entries(self, workspace_with_linked_data):
        """Deleting a cred with api_log entries succeeds."""
        ws, cred_id = workspace_with_linked_data
        result = ws.delete_credential(cred_id)
        assert result is True

    def test_api_log_preserved_after_delete(self, workspace_with_linked_data):
        """API log entries are preserved after credential deletion.

        The audit trail must never be destroyed. The credential_id
        column should be set to NULL on orphaned log entries.
        """
        ws, cred_id = workspace_with_linked_data
        ws.delete_credential(cred_id)

        # --------------------------------------------------------
        # The api_log rows should still exist, with credential_id
        # set to NULL since the credential was deleted.
        # --------------------------------------------------------
        rows = ws.db.fetchall("SELECT * FROM api_log ORDER BY id")
        assert len(rows) == 2
        assert rows[0]["action"] == "GetCallerIdentity"
        assert rows[0]["credential_id"] is None
        assert rows[1]["credential_id"] is None

    def test_credential_gone_after_delete(self, workspace_with_linked_data):
        """The credential row is actually removed from the database."""
        ws, cred_id = workspace_with_linked_data
        ws.delete_credential(cred_id)
        assert ws.get_credential(cred_id) is None

    def test_active_cred_cleared_on_delete(self, workspace_with_linked_data):
        """Active credential is cleared if the deleted one was active."""
        ws, cred_id = workspace_with_linked_data
        ws.active_credential_id = cred_id
        assert ws.active_credential_id == cred_id

        ws.delete_credential(cred_id)
        assert ws.active_credential_id is None

    def test_delete_cred_with_derived_from(self, tmp_path):
        """Deleting a parent credential succeeds when children exist.

        The child credential's derived_from_id should be set to NULL.
        """
        ws = Workspace.create("derived-test", tmp_path)
        parent_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data="{}",
            friendly_name="parent",
        )
        child_id = ws.add_credential(
            provider="aws",
            credential_type="assumed_role",
            secret_data="{}",
            friendly_name="child",
            derived_from_id=parent_id,
        )

        result = ws.delete_credential(parent_id)
        assert result is True

        # --------------------------------------------------------
        # Child should still exist, with derived_from_id NULL.
        # --------------------------------------------------------
        child = ws.get_credential(child_id)
        assert child is not None
        assert child.derived_from_id is None
        ws.close()

    def test_delete_nonexistent_returns_false(self, tmp_path):
        """Deleting a credential that doesn't exist returns False."""
        ws = Workspace.create("empty-test", tmp_path)
        assert ws.delete_credential(999) is False
        ws.close()
