"""Unit tests for discovery/entra_enum_intune_roles."""
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_intune_roles import execute


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
    """OUTCOME: missing Graph token returns clean error dict, no exception."""
    ctx = _make_ctx(_make_store())
    result = execute(ctx)
    assert "error" in result


def test_happy_path_returns_assignments():
    """OUTCOME: With valid token, returns parsed Intune role assignments."""
    role_defs = [
        {"id": "rd-1", "displayName": "Intune Service Administrator"},
        {"id": "rd-2", "displayName": "Help Desk Operator"},
    ]
    assignments = [
        {
            "id": "ra-1",
            "roleDefinitionId": "rd-1",
            "members": ["principal-1"],
            "displayName": "Admins",
        },
        {
            "id": "ra-2",
            "roleDefinitionId": "rd-2",
            "members": ["principal-2"],
            "displayName": "Helpdesk",
        },
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_intune_roles.graph_list",
        side_effect=[role_defs, assignments],
    ):
        result = execute(ctx)

    assert "assignments" in result
    rows = result["assignments"]
    assert len(rows) == 2
    role_names = {r["role_name"] for r in rows}
    assert "Intune Service Administrator" in role_names
    assert "Help Desk Operator" in role_names


def test_intune_service_admin_classifies_as_management_plane():
    """OUTCOME: Intune Administrator → ManagementPlane via real EAM classifier.

    ANTI-GAMIFICATION: real classifier runs against real JSON template.
    """
    role_defs = [{"id": "rd-1", "displayName": "Intune Administrator"}]
    assignments = [
        {
            "id": "ra-1",
            "roleDefinitionId": "rd-1",
            "members": ["p1"],
            "displayName": "Admins",
        }
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_intune_roles.graph_list",
        side_effect=[role_defs, assignments],
    ):
        result = execute(ctx)

    rows = result["assignments"]
    assert rows[0]["tier"] == "ManagementPlane"


def test_unknown_role_classifies_as_unknown():
    """OUTCOME: Custom or unrecognized role name → Unknown tier."""
    role_defs = [{"id": "rd-1", "displayName": "Custom Intune Role X"}]
    assignments = [
        {
            "id": "ra-1",
            "roleDefinitionId": "rd-1",
            "members": ["p1"],
            "displayName": "Group",
        }
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_intune_roles.graph_list",
        side_effect=[role_defs, assignments],
    ):
        result = execute(ctx)

    assert result["assignments"][0]["tier"] == "Unknown"


def test_graph_list_exception_returns_error():
    """OUTCOME: A Graph 403 (raised by graph_list) returns error dict gracefully."""
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_intune_roles.graph_list",
        side_effect=Exception("403 Forbidden"),
    ):
        result = execute(ctx)
    assert "error" in result
