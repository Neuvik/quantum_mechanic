# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_privileged_roles
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_privileged_roles import execute

def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)

def _make_token(token_type: str = "access_token", foci: bool = False) -> EntraToken:
    return EntraToken(
        token_type=token_type,
        value="eyJ.fake",
        resource=GRAPH,
        tenant_id="t",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
        foci=foci,
    )

def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="t")
    if token:
        store.add_token(token)
    return store

def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "entra"
    ctx.session = store
    ctx.log_api_call = MagicMock()
    ctx.info = MagicMock()
    ctx.debug = MagicMock()
    return ctx

class TestNoToken:
    def test_returns_error(self):
        store = _make_store()
        ctx = _build_ctx(store)
        result = execute(ctx)
        assert "error" in result

class TestFociExpansion:
    def test_error_when_expansion_fails(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        with patch("quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result

    def test_uses_expanded_token(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        expanded = _make_token("access_token")
        
        mock_role_defs = [
            {"id": "role-1", "displayName": "Global Administrator"}
        ]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-1",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "admin@contoso.com"
                }
            }
        ]
        
        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.foci_expand",
            return_value=expanded,
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[mock_role_defs, mock_assignments, []]
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)
        
        assert result["status"] == "success"
        assert result["provider"] == "entra"
        assert len(result["assignments"]) == 1
        assert result["assignments"][0]["principal_name"] == "admin@contoso.com"
        assert result["assignments"][0]["tier"] == "ControlPlane"

class TestSuccess:
    def test_enumerates_roles_and_pim(self):
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_role_defs = [
            {"id": "role-1", "displayName": "Global Administrator"},
            {"id": "role-2", "displayName": "User Administrator"}
        ]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-1",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "admin@contoso.com"
                }
            }
        ]
        mock_pim_eligibility = [
            {
                "roleDefinitionId": "role-2",
                "principalId": "user-2",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "user-admin-eligible@contoso.com"
                }
            }
        ]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[mock_role_defs, mock_assignments, mock_pim_eligibility]
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert result["status"] == "success"
        assert result["provider"] == "entra"
        assert len(result["assignments"]) == 2
        
        # Verify active role details
        active = [r for r in result["assignments"] if r["assignment_type"] == "Active/Permanent"][0]
        assert active["principal_name"] == "admin@contoso.com"
        assert active["tier"] == "ControlPlane"

        # Verify eligible PIM role details
        eligible = [r for r in result["assignments"] if r["assignment_type"] == "Eligible (PIM)"][0]
        assert eligible["principal_name"] == "user-admin-eligible@contoso.com"
        assert eligible["tier"] == "ManagementPlane"

    def test_global_admin_assignment_classified_via_eam(self):
        """OUTCOME: A Global Administrator assignment is tagged ControlPlane by the classifier.

        ANTI-GAMIFICATION: We don't patch the classifier — the real classifier runs.
        If classifier breaks or the JSON template is malformed, this test fails.
        """
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        role_defs = [{"id": "rd-1", "displayName": "Global Administrator"}]
        assignments = [{
            "roleDefinitionId": "rd-1",
            "principalId": "user-1",
            "principal": {
                "@odata.type": "#microsoft.graph.user",
                "userPrincipalName": "alice@contoso.com",
            },
        }]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[role_defs, assignments, []],
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assignments_out = result["assignments"]
        assert len(assignments_out) == 1
        assert assignments_out[0]["tier"] == "ControlPlane"
