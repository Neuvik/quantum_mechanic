"""Tests for discovery/entra_enum_app_perms drilldown."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.entra import eam
from quantum_mechanic.techniques.discovery.entra_enum_app_perms import execute


def _ctx_with_app_id(app_id: str = "app-obj-1") -> MagicMock:
    ctx = MagicMock()
    ctx.get_param.side_effect = lambda k: {"app_id": app_id}.get(k)
    fake_token = MagicMock()
    fake_token.value = "fake-token"
    fake_token.token_type = "access_token"
    ctx.session.best_token.return_value = fake_token
    return ctx


def _fake_app_obj(perms=None, display_name="MyApp") -> dict:
    """Build a fake /applications/{id} response body."""
    return {
        "id": "app-obj-1",
        "appId": "guid-1",
        "displayName": display_name,
        "requiredResourceAccess": [
            {
                "resourceAppId": "00000003-0000-0000-c000-000000000000",  # Graph
                "resourceAccess": perms or [],
            }
        ],
    }


def test_missing_app_id_returns_error():
    """OUTCOME: Missing required app_id → status='error'."""
    ctx = MagicMock()
    ctx.get_param.return_value = None
    result = execute(ctx)
    assert result["status"] == "error"
    assert "app_id" in result["error"]


def test_happy_path_returns_permissions_sorted_by_tier():
    """OUTCOME: Perms sorted with ControlPlane first, UserAccess last."""
    ctx = _ctx_with_app_id("app-obj-1")

    app_obj = _fake_app_obj(perms=[
        {"id": "role-cp", "type": "Role"},
        {"id": "role-user", "type": "Role"},
    ])

    class FakeHTTPClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = app_obj
            return r

    def fake_resolve(resource_app_id, perm_entries):
        # Map role-cp → CP perm, role-user → UserAccess perm.
        mapping = {
            "role-cp": "RoleManagement.ReadWrite.Directory",
            "role-user": "User.Read",
        }
        return [mapping[e["id"]] for e in perm_entries]

    with patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.httpx.Client", return_value=FakeHTTPClient()), \
         patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.GraphPermResolver") as MockResolver:
        MockResolver.return_value.resolve_perm_names.side_effect = fake_resolve
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["app_display_name"] == "MyApp"
    perms = result["permissions"]
    assert len(perms) == 2
    # ControlPlane perm should be first
    assert perms[0]["tier"] == eam.TIER_CONTROL_PLANE
    assert perms[0]["name"] == "RoleManagement.ReadWrite.Directory"
    assert perms[0]["kind"] == "Application"


def test_app_not_found_falls_back_to_appid_filter():
    """OUTCOME: 404 on /applications/{id} triggers appId filter lookup."""
    ctx = _ctx_with_app_id("guid-1")

    class FakeHTTPClient:
        def __init__(self):
            self.calls = 0

        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            self.calls += 1
            r = MagicMock()
            if self.calls == 1:
                r.status_code = 404
                return r
            # Second call — appId filter
            assert "$filter=appId eq" in url
            r.status_code = 200
            r.json.return_value = {"value": [_fake_app_obj(perms=[])]}
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.httpx.Client", return_value=FakeHTTPClient()), \
         patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.GraphPermResolver") as MockResolver:
        MockResolver.return_value.resolve_perm_names.return_value = []
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["permissions"] == []


def test_app_lookup_403_returns_denied():
    """OUTCOME: 403 returns status='denied' with required_scope populated."""
    ctx = _ctx_with_app_id("app-obj-1")

    class FakeHTTPClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            r = MagicMock()
            r.status_code = 403
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.httpx.Client", return_value=FakeHTTPClient()):
        result = execute(ctx)

    assert result["status"] == "denied"
    assert result["required_scope"] == "Application.Read.All"


def test_resource_display_name_populated_for_graph():
    """OUTCOME: When resourceAppId is Microsoft Graph GUID, display name is 'Microsoft Graph'."""
    ctx = _ctx_with_app_id("app-obj-1")

    app_obj = _fake_app_obj(perms=[{"id": "role-x", "type": "Role"}])

    class FakeHTTPClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = app_obj
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.httpx.Client", return_value=FakeHTTPClient()), \
         patch("quantum_mechanic.techniques.discovery.entra_enum_app_perms.GraphPermResolver") as MockResolver:
        MockResolver.return_value.resolve_perm_names.return_value = ["User.Read"]
        result = execute(ctx)

    assert result["permissions"][0]["resource_display_name"] == "Microsoft Graph"
