# ================================================================
# TESTS: quantum_mechanic.core.store.findings
# ----------------------------------------------------------------
# WHAT:   Isolated tests for FindingStore (add + list).
#
# WHY:    Severity sort order and INSERT OR IGNORE dedup are the
#         two behaviours that silently corrupt attack paths if
#         wrong. Both need explicit tests.
# ================================================================

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.findings import FindingStore

_FINDING = dict(
    technique_id="discovery/enum_iam",
    tactic="Discovery",
    title="Overprivileged IAM principal",
    severity="high",
    provider="aws",
    description="Principal has wildcard permissions.",
    evidence='{"actions": ["*"]}',
)


@pytest.fixture
def db(workspace_db):
    return workspace_db


@pytest.fixture
def store(workspace_db, workspace_id):
    return FindingStore(workspace_db, workspace_id)


# ================================================================
# add
# ================================================================

class TestFindingStoreAdd:
    def test_returns_integer_id(self, store):
        fid = store.add(**_FINDING)
        assert isinstance(fid, int)
        assert fid >= 1

    def test_all_fields_persisted(self, store):
        store.add(**_FINDING)
        rows = store.list()
        assert len(rows) == 1
        row = rows[0]
        assert row["technique_id"] == _FINDING["technique_id"]
        assert row["title"] == _FINDING["title"]
        assert row["severity"] == _FINDING["severity"]

    def test_optional_mitre_id(self, store):
        fid = store.add(**_FINDING, mitre_id="T1087")
        rows = store.list()
        assert rows[0]["mitre_id"] == "T1087"

    def test_duplicate_is_ignored(self, store):
        """INSERT OR IGNORE — second call with same (technique_id, title) is a no-op."""
        store.add(**_FINDING)
        store.add(**_FINDING)  # exact duplicate
        assert len(store.list()) == 1

    def test_different_title_is_not_duplicate(self, store):
        store.add(**_FINDING)
        finding2 = dict(_FINDING, title="Different title")
        store.add(**finding2)
        assert len(store.list()) == 2


# ================================================================
# list — severity sort order
# ================================================================

class TestFindingStoreList:
    def _add(self, store, severity, title):
        store.add(
            technique_id=f"t/{title}",
            tactic="Discovery",
            title=title,
            severity=severity,
            provider="aws",
            description="x",
            evidence="{}",
        )

    def test_empty_list(self, store):
        assert store.list() == []

    def test_severity_order_critical_first(self, store):
        """Critical > high > medium > low > other."""
        for severity, title in [
            ("low",      "low-finding"),
            ("critical", "critical-finding"),
            ("medium",   "medium-finding"),
            ("high",     "high-finding"),
        ]:
            self._add(store, severity, title)

        rows = store.list()
        severities = [r["severity"] for r in rows]
        expected_order = ["critical", "high", "medium", "low"]
        assert severities == expected_order

    def test_unknown_severity_sorts_last(self, store):
        self._add(store, "info", "info-finding")
        self._add(store, "critical", "crit-finding")
        rows = store.list()
        assert rows[0]["severity"] == "critical"
        assert rows[-1]["severity"] == "info"

    def test_list_returns_dicts(self, store):
        store.add(**_FINDING)
        row = store.list()[0]
        assert isinstance(row, dict)
        for key in ("technique_id", "tactic", "title", "severity", "provider"):
            assert key in row
