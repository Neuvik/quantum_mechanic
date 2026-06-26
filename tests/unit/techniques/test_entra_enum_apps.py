# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_apps
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_apps import execute


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


_SAMPLE_APPS = [
    {
        "id": "app1", "appId": "app-id-1", "displayName": "Internal App",
        "signInAudience": "AzureADMyOrg",
        "passwordCredentials": [{"keyId": "k1"}],
        "keyCredentials": [],
    },
    {
        "id": "app2", "appId": "app-id-2", "displayName": "Multi-Tenant App",
        "signInAudience": "AzureADMultipleOrgs",
        "passwordCredentials": [],
        "keyCredentials": [],
    },
]

_SAMPLE_SPS = [
    {"id": "sp1", "appId": "app-id-1", "displayName": "Internal App", "servicePrincipalType": "Application", "accountEnabled": True},
    {"id": "sp2", "appId": "00000003-0000-0000-c000-000000000000", "displayName": "Microsoft Graph", "servicePrincipalType": "Application", "accountEnabled": True},
]


def _run(apps=_SAMPLE_APPS, sps=_SAMPLE_SPS):
    store = _make_store(_make_token())
    ctx = _build_ctx(store)
    http_mock = MagicMock()
    http_mock.__enter__ = lambda s: http_mock
    http_mock.__exit__ = MagicMock(return_value=False)
    call_count = [0]

    def _graph_list_side_effect(http, url, headers, **kwargs):
        call_count[0] += 1
        return apps if call_count[0] == 1 else sps

    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_apps.graph_list",
        side_effect=_graph_list_side_effect,
    ), patch(
        "quantum_mechanic.techniques.discovery.entra_enum_apps.httpx.Client",
        return_value=http_mock,
    ):
        return execute(ctx)


class TestNoToken:
    def test_returns_error(self):
        result = execute(_build_ctx(_make_store()))
        assert "error" in result


class TestEnumApps:
    def test_applications_list(self):
        result = _run()
        assert len(result["applications"]) == 2

    def test_service_principals_list(self):
        result = _run()
        assert len(result["service_principals"]) == 2

    def test_multi_tenant_count(self):
        result = _run()
        assert result["multi_tenant_count"] == 1

    def test_with_secrets_count(self):
        result = _run()
        assert result["with_secrets_count"] == 1

    def test_tenant_id(self):
        assert _run()["tenant_id"] == "t"

    def test_empty_results(self):
        result = _run(apps=[], sps=[])
        assert result["applications"] == []
        assert result["service_principals"] == []
        assert result["apps"] == []
        assert result["multi_tenant_count"] == 0
        assert result["with_secrets_count"] == 0

    def test_unified_apps_list(self):
        result = _run()
        apps = result["apps"]
        assert len(apps) == 4
        # Verify app registration
        assert apps[0]["displayName"] == "Internal App"
        assert apps[0]["type"] == "App Registration"
        assert apps[0]["secrets"] == 1
        assert apps[0]["enabled"] == "—"
        # Verify service principal
        assert apps[2]["displayName"] == "Internal App"
        assert apps[2]["type"] == "Service Principal"
        assert apps[2]["secrets"] == 0
        assert apps[2]["enabled"] == "Yes"

    def test_foci_expansion_error(self):
        store = _make_store(_make_token("refresh_token"))
        ctx = _build_ctx(store)
        with patch("quantum_mechanic.techniques.discovery.entra_enum_apps.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result

    def test_highest_perm_tier_emitted_per_app(self):
        """OUTCOME: Apps with Graph permissions get a `highest_perm_tier` column.

        ANTI-GAMIFICATION: real classifier — assertions exercise the JSON template.
        """
        apps_with_perm = [{
            "id": "app-1",
            "appId": "appid-1",
            "displayName": "Privileged App",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "requiredResourceAccess": [{
                "resourceAppId": "00000003-0000-0000-c000-000000000000",  # Graph
                "resourceAccess": [{"id": "perm-id-1", "type": "Role"}],
            }],
            # Pre-resolved permission name list (Phase A convenience — Phase B resolves IDs).
            "_resolved_perms": ["RoleManagement.ReadWrite.Directory"],
        }]

        store = _make_store(_make_token("access_token"))
        ctx = _build_ctx(store)
        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_apps.graph_list",
            side_effect=[apps_with_perm, []],  # applications, servicePrincipals
        ):
            result = execute(ctx)

        enriched_app = next(a for a in result["apps"] if a["displayName"] == "Privileged App")
        assert enriched_app["highest_perm_tier"] == "ControlPlane"


class TestLootMetadata:
    def test_loot_metadata_configured(self):
        meta = getattr(execute, "__technique__", None)
        assert meta is not None
        assert meta.loot_items_key == "apps"
        schema = meta.loot_schema
        assert isinstance(schema, list)
        assert len(schema) > 0
        assert schema[0][0] == "displayName"
