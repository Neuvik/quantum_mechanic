# ================================================================
# TESTS: techniques/discovery/azure_enum_resource_groups
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.token_store import ARM, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.azure_enum_resource_groups import execute

_SAMPLE_SUBS = [
    {"subscriptionId": "sub-111", "displayName": "Prod", "state": "Enabled", "tenantId": "tid"},
    {"subscriptionId": "sub-222", "displayName": "Dev", "state": "Disabled", "tenantId": "tid"},
]

_SAMPLE_RGS_PROD = [
    {"name": "rg-app", "location": "eastus", "properties": {"provisioningState": "Succeeded"}, "id": "/subscriptions/sub-111/resourceGroups/rg-app"},
    {"name": "rg-net", "location": "eastus", "properties": {"provisioningState": "Succeeded"}, "id": "/subscriptions/sub-111/resourceGroups/rg-net"},
]

_SAMPLE_RESOURCES = [
    {"id": "/subscriptions/sub-111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"},
    {"id": "/subscriptions/sub-111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm2"},
    {"id": "/subscriptions/sub-111/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet1"},
]


def _make_access_token() -> EntraToken:
    return EntraToken(
        token_type="access_token",
        resource=ARM,
        value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0aWQifQ.sig",
        tenant_id="tid",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=False,
    )


def _make_foci_token() -> EntraToken:
    return EntraToken(
        token_type="refresh_token",
        resource="",
        value="foci-rt",
        tenant_id="tid",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=True,
    )


def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = store
    ctx.info = MagicMock()
    return ctx


def _run(
    rgs: list[dict] | None = None,
    resources: list[dict] | None = None,
    subs: list[dict] | None = None,
    foci: bool = False,
) -> dict:
    store = EntraTokenStore(tenant_id="tid")
    store.add_token(_make_foci_token() if foci else _make_access_token())
    ctx = _build_ctx(store)
    sub_list = subs if subs is not None else _SAMPLE_SUBS
    rg_list = rgs if rgs is not None else _SAMPLE_RGS_PROD
    res_list = resources if resources is not None else _SAMPLE_RESOURCES

    # arm_list returns different data depending on call: subs → rgs → resources
    call_results = [sub_list, rg_list, res_list]
    call_index = [0]

    def _arm_list_side_effect(http, url, headers, **kwargs):
        result = call_results[min(call_index[0], len(call_results) - 1)]
        call_index[0] += 1
        return result

    http_mock = MagicMock()
    http_mock.__enter__ = lambda s: http_mock
    http_mock.__exit__ = MagicMock(return_value=False)

    with patch(
        "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.arm_list",
        side_effect=_arm_list_side_effect,
    ), patch(
        "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.httpx.Client",
        return_value=http_mock,
    ):
        return execute(ctx)


class TestNoToken:
    def test_returns_error_when_no_token(self):
        store = EntraTokenStore(tenant_id="tid")
        ctx = _build_ctx(store)
        result = execute(ctx)
        assert "error" in result
        assert "ARM" in result["error"]

    def test_returns_error_when_foci_expand_fails(self):
        store = EntraTokenStore(tenant_id="tid")
        store.add_token(_make_foci_token())
        ctx = _build_ctx(store)
        with patch(
            "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.foci_expand",
            return_value=None,
        ):
            result = execute(ctx)
        assert "error" in result
        assert "FOCI" in result["error"]


class TestSuccessPath:
    def test_returns_resource_groups(self):
        result = _run()
        assert result["total"] == 2
        assert len(result["resource_groups"]) == 2

    def test_only_enabled_subscriptions_queried(self):
        # sub-222 is Disabled — only sub-111 (Enabled) should be queried
        result = _run()
        assert result["subscription_count"] == 1

    def test_subscription_id_attached_to_rg(self):
        result = _run()
        for rg in result["resource_groups"]:
            assert rg["subscription_id"] == "sub-111"

    def test_resource_count_populated(self):
        result = _run()
        rg_map = {rg["name"]: rg for rg in result["resource_groups"]}
        assert rg_map["rg-app"]["resource_count"] == 2
        assert rg_map["rg-net"]["resource_count"] == 1

    def test_provisioning_state_extracted(self):
        result = _run()
        assert result["resource_groups"][0]["provisioning_state"] == "Succeeded"

    def test_tenant_id_in_result(self):
        result = _run()
        assert result["tenant_id"] == "tid"

    def test_provider_field(self):
        result = _run()
        assert result["provider"] == "entra"

    def test_empty_subscriptions(self):
        result = _run(subs=[])
        assert result["total"] == 0
        assert result["resource_groups"] == []
        assert result["subscription_count"] == 0

    def test_all_disabled_subscriptions(self):
        disabled = [{"subscriptionId": "x", "displayName": "X", "state": "Disabled"}]
        result = _run(subs=disabled)
        assert result["total"] == 0
        assert result["subscription_count"] == 0


class TestFociExpansion:
    def test_foci_token_triggers_expand(self):
        store = EntraTokenStore(tenant_id="tid")
        store.add_token(_make_foci_token())
        ctx = _build_ctx(store)
        expanded = _make_access_token()
        http_mock = MagicMock()
        http_mock.__enter__ = lambda s: http_mock
        http_mock.__exit__ = MagicMock(return_value=False)

        with patch(
            "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.foci_expand",
            return_value=expanded,
        ) as mock_expand, patch(
            "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.arm_list",
            side_effect=[_SAMPLE_SUBS, _SAMPLE_RGS_PROD, _SAMPLE_RESOURCES],
        ), patch(
            "quantum_mechanic.techniques.discovery.azure_enum_resource_groups.httpx.Client",
            return_value=http_mock,
        ):
            result = execute(ctx)

        mock_expand.assert_called_once_with(store, ARM)
        assert result["total"] == 2
