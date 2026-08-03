# ================================================================
# TESTS: quantum_mechanic.core.store.evidence
# ----------------------------------------------------------------
# WHAT:   Isolated tests for EvidenceStore (evidence saves and
#         api_log appends).
#
# WHY:    Evidence ordering drives the ATTACK_PATH.md timeline.
#         API log integrity is the audit trail — it must survive
#         credential deletion (FK to NULL, not DELETE).
# ================================================================

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.evidence import EvidenceStore


@pytest.fixture
def db(workspace_db):
    return workspace_db


@pytest.fixture
def store(workspace_db, workspace_id):
    return EvidenceStore(workspace_db, workspace_id)


# ================================================================
# save / list
# ================================================================

class TestEvidenceStoreSave:
    def test_save_returns_integer_id(self, store):
        ev_id = store.save("discovery/whoami", '{"user": "alice"}')
        assert isinstance(ev_id, int)
        assert ev_id >= 1

    def test_saved_evidence_appears_in_list(self, store):
        store.save("discovery/whoami", '{"user": "alice"}')
        rows = store.list()
        assert len(rows) == 1
        assert rows[0]["technique_id"] == "discovery/whoami"

    def test_list_is_ordered_by_timestamp_ascending(self, store):
        """Chronological order is required for the technique timeline."""
        store.save("discovery/whoami", '{"order": 1}')
        store.save("discovery/enum_iam", '{"order": 2}')
        store.save("escalation/assume_role_chain", '{"order": 3}')
        rows = store.list()
        technique_ids = [r["technique_id"] for r in rows]
        # The list must be in insertion (timestamp) order
        assert technique_ids[0] == "discovery/whoami"
        assert technique_ids[-1] == "escalation/assume_role_chain"

    def test_empty_list_on_empty_store(self, store):
        assert store.list() == []

    def test_optional_credential_id(self, store):
        ev_id = store.save("discovery/whoami", "{}", credential_id=None)
        rows = store.list()
        assert rows[0]["credential_id"] is None

    def test_list_returns_dicts(self, store):
        store.save("t", "{}")
        row = store.list()[0]
        assert isinstance(row, dict)
        assert "technique_id" in row
        assert "output_json" in row
        assert "timestamp" in row


# ================================================================
# log_api_call
# ================================================================

class TestEvidenceStoreLogApiCall:
    def test_log_returns_integer_id(self, store):
        log_id = store.log_api_call(provider="aws", action="sts:GetCallerIdentity")
        assert isinstance(log_id, int)
        assert log_id >= 1

    def test_all_optional_fields_accepted(self, store):
        log_id = store.log_api_call(
            provider="aws",
            action="iam:ListRoles",
            credential_id=None,
            service="iam",
            request_params='{"MaxItems": 100}',
            response_status=200,
            response_summary="42 roles",
            technique_id="discovery/enum_iam",
            duration_ms=312,
        )
        assert log_id >= 1

    def test_sequential_logs_have_unique_ids(self, store):
        id1 = store.log_api_call(provider="aws", action="sts:GetCallerIdentity")
        id2 = store.log_api_call(provider="aws", action="iam:ListUsers")
        assert id1 != id2
