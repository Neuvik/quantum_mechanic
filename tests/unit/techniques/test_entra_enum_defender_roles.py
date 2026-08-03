"""Unit tests for discovery/entra_enum_defender_roles."""
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_defender_roles import execute


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def _make_access_token() -> EntraToken:
    return EntraToken(
        token_type="access_token",
        value="eyJ.fake.access",
        resource=GRAPH,
        tenant_id="tenant-123",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
    )


def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-123", user_upn="alice@contoso.com")
    if token:
        store.add_token(token)
    return store


def _make_ctx(store):
    ctx = MagicMock()
    ctx.session = store
    ctx.provider_name = "entra"
    return ctx


def test_no_token_returns_error():
    """OUTCOME: missing Graph token returns clean error dict."""
    ctx = _make_ctx(_make_store())
    result = execute(ctx)
    assert "error" in result


def test_happy_path_returns_assignments():
    """OUTCOME: returns parsed Defender role assignments."""
    assignments = [
        {
            "id": "ra-1",
            "roleDefinition": {"id": "rd-1", "displayName": "Security Administrator"},
            "principal": {
                "@odata.type": "#microsoft.graph.user",
                "id": "user-1",
                "userPrincipalName": "alice@contoso.com",
            },
        },
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_defender_roles.graph_list",
        return_value=assignments,
    ):
        result = execute(ctx)

    assert "assignments" in result
    rows = result["assignments"]
    assert len(rows) == 1
    assert rows[0]["role_name"] == "Security Administrator"
    assert rows[0]["principal_name"] == "alice@contoso.com"


def test_security_admin_classifies_as_management_plane():
    """OUTCOME: Security Administrator → ManagementPlane via real EAM classifier."""
    assignments = [
        {
            "id": "ra-1",
            "roleDefinition": {"id": "rd-1", "displayName": "Security Administrator"},
            "principal": {"id": "p1", "userPrincipalName": "x@y.com"},
        },
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_defender_roles.graph_list",
        return_value=assignments,
    ):
        result = execute(ctx)

    assert result["assignments"][0]["tier"] == "ManagementPlane"


def test_403_returns_error_gracefully():
    """OUTCOME: 403 on /security/roleAssignments returns error dict, no crash."""
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_defender_roles.graph_list",
        side_effect=Exception("403 Forbidden"),
    ):
        result = execute(ctx)
    assert "error" in result


def test_empty_assignments_returns_clean_result():
    """OUTCOME: zero assignments returns empty list, status success."""
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_defender_roles.graph_list",
        return_value=[],
    ):
        result = execute(ctx)

    assert result.get("status") == "success"
    assert result["assignments"] == []
