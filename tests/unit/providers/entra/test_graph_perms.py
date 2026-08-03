"""Tests for the Graph permission UUID→name resolver."""
from unittest.mock import MagicMock

from quantum_mechanic.providers.entra.graph_perms import GraphPermResolver

_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def _mock_sp_response(app_roles, scopes):
    """Build a /servicePrincipals/{id}?$expand=... style response."""
    return {
        "value": [{
            "id": "sp-id",
            "appId": _GRAPH_APP_ID,
            "appRoles": app_roles,
            "oauth2PermissionScopes": scopes,
        }]
    }


def test_resolve_perm_names_returns_role_value_for_role_entry():
    """OUTCOME: Application permission (type=Role) UUID resolves to the appRole's `value` field."""
    http = MagicMock()
    http.get.return_value = MagicMock(
        status_code=200,
        json=lambda: _mock_sp_response(
            app_roles=[{"id": "role-uuid-1", "value": "RoleManagement.ReadWrite.Directory"}],
            scopes=[],
        ),
    )
    resolver = GraphPermResolver(http=http, headers={"Authorization": "Bearer x"})
    names = resolver.resolve_perm_names(
        resource_app_id=_GRAPH_APP_ID,
        perm_entries=[{"id": "role-uuid-1", "type": "Role"}],
    )
    assert names == ["RoleManagement.ReadWrite.Directory"]


def test_resolve_perm_names_returns_scope_value_for_scope_entry():
    """OUTCOME: Delegated permission (Scope) UUID resolves to scope's value field."""
    http = MagicMock()
    http.get.return_value = MagicMock(
        status_code=200,
        json=lambda: _mock_sp_response(
            app_roles=[],
            scopes=[{"id": "scope-uuid-1", "value": "User.Read"}],
        ),
    )
    resolver = GraphPermResolver(http=http, headers={})
    names = resolver.resolve_perm_names(
        resource_app_id=_GRAPH_APP_ID,
        perm_entries=[{"id": "scope-uuid-1", "type": "Scope"}],
    )
    assert names == ["User.Read"]


def test_resolve_perm_names_drops_unknown_uuids_silently():
    """OUTCOME: Unknown perm UUIDs are not raised — they're just absent from results."""
    http = MagicMock()
    http.get.return_value = MagicMock(
        status_code=200,
        json=lambda: _mock_sp_response(
            app_roles=[{"id": "role-uuid-1", "value": "Known.Perm"}],
            scopes=[],
        ),
    )
    resolver = GraphPermResolver(http=http, headers={})
    names = resolver.resolve_perm_names(
        resource_app_id=_GRAPH_APP_ID,
        perm_entries=[
            {"id": "role-uuid-1", "type": "Role"},
            {"id": "totally-fake-uuid", "type": "Role"},
        ],
    )
    assert names == ["Known.Perm"]


def test_resolve_perm_names_caches_per_resource_app_id():
    """OUTCOME: Second call to the same resource_app_id doesn't trigger another HTTP get."""
    http = MagicMock()
    http.get.return_value = MagicMock(
        status_code=200,
        json=lambda: _mock_sp_response(
            app_roles=[{"id": "role-uuid-1", "value": "Perm.One"}],
            scopes=[],
        ),
    )
    resolver = GraphPermResolver(http=http, headers={})

    resolver.resolve_perm_names(_GRAPH_APP_ID, [{"id": "role-uuid-1", "type": "Role"}])
    resolver.resolve_perm_names(_GRAPH_APP_ID, [{"id": "role-uuid-1", "type": "Role"}])

    assert http.get.call_count == 1


def test_resolve_perm_names_empty_entries_returns_empty():
    """OUTCOME: Empty perm_entries list returns empty list with no HTTP call."""
    http = MagicMock()
    resolver = GraphPermResolver(http=http, headers={})
    assert resolver.resolve_perm_names(_GRAPH_APP_ID, []) == []
    assert http.get.call_count == 0


def test_resolve_perm_names_non_200_returns_empty():
    """OUTCOME: 403/404 from Graph results in empty list (graceful degradation)."""
    http = MagicMock()
    http.get.return_value = MagicMock(status_code=403, json=lambda: {})
    resolver = GraphPermResolver(http=http, headers={})
    names = resolver.resolve_perm_names(
        _GRAPH_APP_ID,
        [{"id": "role-uuid-1", "type": "Role"}],
    )
    assert names == []
