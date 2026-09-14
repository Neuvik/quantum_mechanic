# ================================================================
# TESTS: techniques/discovery/azure_enum_resource_groups
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.azure_enum_resource_groups import execute


def _make_sdk_sub(sub_id: str, display_name: str, state: str | None) -> MagicMock:
    sub = MagicMock()
    sub.subscription_id = sub_id
    sub.display_name = display_name
    sub.state = state
    return sub


def _make_sdk_rg(
    name: str, location: str, sub_id: str, provisioning_state: str | None
) -> MagicMock:
    rg = MagicMock()
    rg.name = name
    rg.location = location
    rg.id = f"/subscriptions/{sub_id}/resourceGroups/{name}"
    rg.tags = None
    rg.properties = MagicMock()
    rg.properties.provisioning_state = provisioning_state
    return rg


def _make_sdk_resource(resource_id: str) -> MagicMock:
    r = MagicMock()
    r.id = resource_id
    return r


_SAMPLE_SUBS = [
    _make_sdk_sub("sub-111", "Prod", "Enabled"),
    _make_sdk_sub("sub-222", "Dev", "Disabled"),
]

_SAMPLE_RGS_PROD = [
    _make_sdk_rg("rg-app", "eastus", "sub-111", "Succeeded"),
    _make_sdk_rg("rg-net", "eastus", "sub-111", "Succeeded"),
]

_SAMPLE_RESOURCES = [
    _make_sdk_resource("/subscriptions/sub-111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"),
    _make_sdk_resource("/subscriptions/sub-111/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm2"),
    _make_sdk_resource("/subscriptions/sub-111/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet1"),
]


def _build_ctx(provider_name: str = "azure") -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = MagicMock()
    ctx.provider_name = provider_name
    ctx.info = MagicMock()
    ctx.whoami.return_value = MagicMock(tenant_id="tid")
    return ctx


def _run(
    subs: list | None = None,
    rgs: list | None = None,
    resources: list | None = None,
    ctx: MagicMock | None = None,
) -> dict:
    ctx = ctx if ctx is not None else _build_ctx()
    sub_list = subs if subs is not None else _SAMPLE_SUBS
    rg_list = rgs if rgs is not None else _SAMPLE_RGS_PROD
    res_list = resources if resources is not None else _SAMPLE_RESOURCES

    with patch("azure.mgmt.subscription.SubscriptionClient") as mock_sub_client, patch(
        "azure.mgmt.resource.resources.ResourceManagementClient"
    ) as mock_resource_client:
        mock_sub_client.return_value.subscriptions.list.return_value = sub_list
        mock_resource_client.return_value.resource_groups.list.return_value = rg_list
        mock_resource_client.return_value.resources.list.return_value = res_list
        return execute(ctx)


class TestSuccessPath:
    def test_returns_resource_groups(self):
        result = _run()
        assert "error" not in result
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

    def test_provider_field_reflects_azure(self):
        """Proves the fix: an 'azure'-provider credential can run this technique."""
        ctx = _build_ctx(provider_name="azure")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["provider"] == "azure"

    def test_provider_field_reflects_entra_bridge(self):
        ctx = _build_ctx(provider_name="entra")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["provider"] == "entra"

    def test_empty_subscriptions(self):
        result = _run(subs=[])
        assert result["total"] == 0
        assert result["resource_groups"] == []
        assert result["subscription_count"] == 0

    def test_all_disabled_subscriptions(self):
        disabled = [_make_sdk_sub("x", "X", "Disabled")]
        result = _run(subs=disabled)
        assert result["total"] == 0
        assert result["subscription_count"] == 0

    def test_state_enum_value_extracted_for_filtering(self):
        """The SDK may return `state` as an enum-like object exposing `.value`
        instead of a plain string — the enabled-subscription filter must
        still work correctly."""
        enum_state = MagicMock()
        enum_state.value = "Enabled"
        sub = _make_sdk_sub("sub-enum", "EnumSub", "placeholder")
        sub.state = enum_state
        result = _run(subs=[sub], rgs=[], resources=[])
        assert result["subscription_count"] == 1

    def test_tags_default_to_empty_dict_when_none(self):
        result = _run()
        for rg in result["resource_groups"]:
            assert rg["tags"] == {}

    def test_missing_provisioning_state_defaults_empty(self):
        rg = _make_sdk_rg("rg-nostate", "eastus", "sub-111", None)
        result = _run(rgs=[rg], resources=[])
        assert result["resource_groups"][0]["provisioning_state"] == ""


class TestErrorHandling:
    def test_returns_error_dict_on_sdk_failure(self):
        ctx = _build_ctx()
        with patch("azure.mgmt.subscription.SubscriptionClient") as mock_sub_client:
            mock_sub_client.return_value.subscriptions.list.side_effect = Exception(
                "AuthorizationFailed"
            )
            result = execute(ctx)
        assert "error" in result
        assert "AuthorizationFailed" in result["error"]
        assert result["resource_groups"] == []

    def test_resources_list_failure_does_not_abort(self):
        """If the per-subscription resources.list() call fails (e.g. transient
        error), resource_count should default to 0 rather than aborting the
        whole technique."""
        ctx = _build_ctx()
        with patch("azure.mgmt.subscription.SubscriptionClient") as mock_sub_client, patch(
            "azure.mgmt.resource.resources.ResourceManagementClient"
        ) as mock_resource_client:
            mock_sub_client.return_value.subscriptions.list.return_value = _SAMPLE_SUBS
            mock_resource_client.return_value.resource_groups.list.return_value = _SAMPLE_RGS_PROD
            mock_resource_client.return_value.resources.list.side_effect = Exception("boom")
            result = execute(ctx)
        assert "error" not in result
        for rg in result["resource_groups"]:
            assert rg["resource_count"] == 0

    def test_whoami_failure_does_not_abort_execution(self):
        ctx = _build_ctx()
        ctx.whoami.side_effect = Exception("whoami failed")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["tenant_id"] is None
        assert result["total"] == 2
