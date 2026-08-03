# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_privileged_roles
# ================================================================

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.graph import GraphAccessError
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_privileged_roles import execute


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


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
        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.foci_expand",
            return_value=None,
        ):
            result = execute(ctx)
        assert "error" in result

    def test_uses_expanded_token(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        expanded = _make_token("access_token")

        mock_role_defs = [{"id": "role-1", "displayName": "Global Administrator"}]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-1",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "admin@contoso.com",
                },
            }
        ]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.foci_expand",
            return_value=expanded,
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[mock_role_defs, mock_assignments, []],
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
            side_effect=[mock_role_defs, mock_assignments, mock_pim_eligibility, []],
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


class TestPimActivatedDistinction:
    def test_activated_pim_assignment_tagged_separately_with_expiry(self):
        """OUTCOME: An active assignment cross-referenced in activated PIM
        schedule instances is labeled Activated (PIM) with expiry metadata."""
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_role_defs = [{"id": "role-1", "displayName": "Global Administrator"}]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-1",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "alice@fabrikam.example",
                },
            }
        ]
        mock_pim_eligibility = []
        mock_activated_instances = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-1",
                "endDateTime": "2026-07-30T18:00:00Z",
            }
        ]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[
                mock_role_defs,
                mock_assignments,
                mock_pim_eligibility,
                mock_activated_instances,
            ],
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert len(result["assignments"]) == 1
        assignment = result["assignments"][0]
        assert assignment["assignment_type"] == "Activated (PIM)"
        assert assignment["expires_at"] == "2026-07-30T18:00:00Z"

    def test_standing_assignment_has_no_expiry(self):
        """OUTCOME: An active assignment absent from activated schedule
        instances remains a standing permanent admin with no expiry."""
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_role_defs = [{"id": "role-1", "displayName": "Global Administrator"}]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-2",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "bob@fabrikam.example",
                },
            }
        ]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[mock_role_defs, mock_assignments, [], []],
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assignment = result["assignments"][0]
        assert assignment["assignment_type"] == "Active/Permanent"
        assert assignment["expires_at"] is None


class TestPartialVisibility:
    def test_returns_partial_when_optional_pim_probes_are_scope_denied(self):
        """OUTCOME: Base privileged-role enumeration stays usable, but the
        technique reports partial visibility and missing scopes when optional
        PIM probes are denied."""
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_role_defs = [{"id": "role-1", "displayName": "Global Administrator"}]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-2",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "bob@fabrikam.example",
                },
            }
        ]

        eligibility_denied = GraphAccessError(
            url="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal",
            status=403,
            code="PermissionScopeNotGranted",
            message="missing RoleEligibilitySchedule.Read.Directory",
            scope_hint="RoleEligibilitySchedule.Read.Directory",
        )
        activated_denied = GraphAccessError(
            url=(
                "https://graph.microsoft.com/v1.0/roleManagement/directory/"
                "roleAssignmentScheduleInstances?$filter=assignmentType eq 'Activated'"
            ),
            status=403,
            code="PermissionScopeNotGranted",
            message="missing RoleAssignmentSchedule.Read.Directory",
            scope_hint="RoleAssignmentSchedule.Read.Directory",
        )

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[
                mock_role_defs,
                mock_assignments,
                eligibility_denied,
                activated_denied,
            ],
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert result["status"] == "partial"
        assert len(result["assignments"]) == 1
        assert result["visibility"] == {
            "active_assignments": True,
            "pim_eligibility": False,
            "pim_activated": False,
        }
        assert result["missing_scopes"] == [
            "RoleAssignmentSchedule.Read.Directory",
            "RoleEligibilitySchedule.Read.Directory",
        ]
        assert result["partial_reasons"] == [
            "PIM eligibility visibility denied",
            "PIM activated-assignment visibility denied",
        ]

    def test_returns_success_when_optional_pim_probes_are_empty_but_allowed(self):
        """OUTCOME: Empty optional PIM views are still a full success when
        Graph allowed the probes."""
        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)

        mock_role_defs = [{"id": "role-1", "displayName": "Global Administrator"}]
        mock_assignments = [
            {
                "roleDefinitionId": "role-1",
                "principalId": "user-2",
                "principal": {
                    "@odata.type": "#microsoft.graph.user",
                    "userPrincipalName": "bob@fabrikam.example",
                },
            }
        ]

        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.graph_list",
            side_effect=[mock_role_defs, mock_assignments, [], []],
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_privileged_roles.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)

        assert result["status"] == "success"
        assert result["visibility"] == {
            "active_assignments": True,
            "pim_eligibility": True,
            "pim_activated": True,
        }
        assert result["missing_scopes"] == []
        assert result["partial_reasons"] == []
