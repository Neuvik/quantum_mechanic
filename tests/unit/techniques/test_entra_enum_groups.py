# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_groups
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_groups import _classify_group, execute


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _make_token(token_type: str = "access_token") -> EntraToken:
    return EntraToken(
        token_type=token_type,
        value="eyJ.fake",
        resource=GRAPH,
        tenant_id="t",
        expires_at=_future(),
        foci=True,
        client_id=FOCI_DEFAULT_CLIENT,
    )


def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="t")
    if token:
        store.add_token(token)
    return store


def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = store
    ctx.log_api_call = MagicMock()
    return ctx


_SAMPLE_GROUPS = [
    {
        "id": "g1", "displayName": "Security Team",
        "groupTypes": [], "securityEnabled": True, "mailEnabled": False,
        "isAssignableToRole": False,
    },
    {
        "id": "g2", "displayName": "M365 Group",
        "groupTypes": ["Unified"], "securityEnabled": False, "mailEnabled": True,
        "isAssignableToRole": False,
    },
    {
        "id": "g3", "displayName": "Dynamic Security",
        "groupTypes": ["DynamicMembership"], "securityEnabled": True, "mailEnabled": False,
        "isAssignableToRole": False, "membershipRule": "user.department -eq 'Security'",
    },
    {
        "id": "g4", "displayName": "Privileged Role Group",
        "groupTypes": [], "securityEnabled": True, "mailEnabled": False,
        "isAssignableToRole": True,
    },
]


def _run(groups: list = _SAMPLE_GROUPS) -> dict:
    store = _make_store(_make_token())
    ctx = _build_ctx(store)
    http_mock = MagicMock()
    http_mock.__enter__ = lambda s: http_mock
    http_mock.__exit__ = MagicMock(return_value=False)
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_groups.graph_list",
        return_value=groups,
    ), patch(
        "quantum_mechanic.techniques.discovery.entra_enum_groups.httpx.Client",
        return_value=http_mock,
    ):
        return execute(ctx)


# ----------------------------------------------------------------
# _classify_group
# ----------------------------------------------------------------

class TestClassifyGroup:
    def test_role_assignable(self):
        assert _classify_group({"isAssignableToRole": True, "groupTypes": [], "securityEnabled": True}) == "role-assignable"

    def test_m365(self):
        assert _classify_group({"groupTypes": ["Unified"], "isAssignableToRole": False}) == "M365"

    def test_security_dynamic(self):
        assert _classify_group({"groupTypes": ["DynamicMembership"], "securityEnabled": True, "isAssignableToRole": False}) == "security-dynamic"

    def test_m365_dynamic(self):
        assert _classify_group({"groupTypes": ["Unified", "DynamicMembership"], "isAssignableToRole": False}) == "M365-dynamic"

    def test_security(self):
        assert _classify_group({"groupTypes": [], "securityEnabled": True, "mailEnabled": False, "isAssignableToRole": False}) == "security"

    def test_other(self):
        assert _classify_group({"groupTypes": [], "securityEnabled": False, "mailEnabled": True, "isAssignableToRole": False}) == "other"


# ----------------------------------------------------------------
# execute()
# ----------------------------------------------------------------

class TestNoToken:
    def test_returns_error(self):
        result = execute(_build_ctx(_make_store()))
        assert "error" in result


class TestEnumGroups:
    def test_total_count(self):
        assert _run()["total"] == 4

    def test_by_type_classification(self):
        by_type = _run()["by_type"]
        assert by_type.get("security") == 1
        assert by_type.get("M365") == 1
        assert by_type.get("security-dynamic") == 1
        assert by_type.get("role-assignable") == 1

    def test_groups_list(self):
        result = _run()
        assert len(result["groups"]) == 4

    def test_tenant_id(self):
        assert _run()["tenant_id"] == "t"

    def test_empty_tenant(self):
        result = _run(groups=[])
        assert result["total"] == 0
        assert result["by_type"] == {}

    def test_foci_expansion_error(self):
        store = _make_store(_make_token("refresh_token"))
        ctx = _build_ctx(store)
        with patch("quantum_mechanic.techniques.discovery.entra_enum_groups.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result
