"""ANTI-GAMIFICATION guard tests for Phase A2.

Every Entra enum technique must return status="denied" (not "success",
not empty items, not a bare {"error": ...}) when graph_list raises
GraphAccessError. If any technique regresses to swallowing the 403,
the runner will print a misleading green ✓ — which is the whole class
of bug this phase exists to prevent.

Each test mocks graph_list to raise GraphAccessError and asserts the
returned dict has:
  - status == "denied"
  - error message present
  - required_scope populated from the URL prefix (when known)
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.entra.graph import GraphAccessError


def _mock_entra_ctx(monkeypatch=None) -> MagicMock:
    """Build a ctx.session that always yields a fake Graph token."""
    ctx = MagicMock()
    ctx.get_param.return_value = None
    ctx.info = MagicMock()
    ctx.debug = MagicMock()
    fake_token = MagicMock()
    fake_token.value = "fake-token"
    fake_token.token_type = "access_token"
    ctx.session.best_token.return_value = fake_token
    ctx.session.tenant_id = "tenant-id-1"
    return ctx


def _denied_error(url: str = "https://graph.microsoft.com/v1.0/users", scope_hint: str | None = "User.Read.All") -> GraphAccessError:
    return GraphAccessError(
        url=url,
        status=403,
        code="Authorization_RequestDenied",
        message="The caller is not authorized",
        scope_hint=scope_hint,
    )


@pytest.mark.parametrize("mod_path,url_frag,expected_scope", [
    ("quantum_mechanic.techniques.discovery.entra_enum_users", "/users", "User.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_groups", "/groups", "Group.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_devices", "/devices", "Device.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_apps", "/applications", "Application.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_defender_roles", "/security/roleAssignments", "SecurityIdentitiesSensors.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_intune_roles", "/deviceManagement/roleAssignments", "DeviceManagementRBAC.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_access_packages", "/identityGovernance/entitlementManagement", "EntitlementManagement.Read.All"),
    ("quantum_mechanic.techniques.discovery.entra_enum_privileged_roles", "/roleManagement/directory", "RoleManagement.Read.Directory"),
    ("quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies", "/identity/conditionalAccess/policies", "Policy.Read.ConditionalAccess"),
])
def test_technique_returns_denied_on_graph_access_error(mod_path, url_frag, expected_scope):
    """OUTCOME: When graph_list raises GraphAccessError, technique returns
    status="denied" with required_scope populated — NOT status="success".

    ANTI-GAMIFICATION: If someone reintroduces the "log and return []" bug
    in any of these techniques, this test proves it by showing a green ✓
    (status="success") where the operator should see red ✗ (denied).
    """
    import importlib
    mod = importlib.import_module(mod_path)

    err = _denied_error(url=f"https://graph.microsoft.com/v1.0{url_frag}", scope_hint=expected_scope)

    ctx = _mock_entra_ctx()
    with patch(f"{mod_path}.graph_list", side_effect=err):
        result = mod.execute(ctx)

    assert result.get("status") == "denied", (
        f"{mod_path}: expected status='denied' when graph_list raises GraphAccessError, "
        f"got {result.get('status')!r} — this is the silent-403 bug regressing."
    )
    assert result.get("error"), f"{mod_path}: denied result missing 'error' field"
    assert result.get("required_scope") == expected_scope, (
        f"{mod_path}: expected required_scope={expected_scope!r}, got {result.get('required_scope')!r}"
    )


def test_group_members_returns_denied_on_graph_access_error():
    """OUTCOME: entra_enum_group_members returns status='denied' when graph_list
    for members raises GraphAccessError.

    Separate from the parametrized test because group_members needs
    ctx.get_param('group_id') set.
    """
    from quantum_mechanic.techniques.discovery import entra_enum_group_members

    ctx = _mock_entra_ctx()
    ctx.get_param.side_effect = lambda key: "group-id-1" if key == "group_id" else None

    err = _denied_error(
        url="https://graph.microsoft.com/v1.0/groups/group-id-1/members",
        scope_hint="Group.Read.All",
    )
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_group_members.graph_list",
        side_effect=err,
    ):
        result = entra_enum_group_members.execute(ctx)

    assert result.get("status") == "denied"
    assert result.get("error")
    assert result.get("required_scope") == "Group.Read.All"
