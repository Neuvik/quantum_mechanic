# ================================================================
# TESTS: techniques/discovery/azure_enum_subscriptions
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.azure_enum_subscriptions import execute


def _make_sdk_sub(sub_id: str, display_name: str, state: str) -> MagicMock:
    """Build a fake azure.mgmt.subscription.models.Subscription object.

    The real SDK returns a `state` field that may be a plain string or an
    enum-like object exposing `.value` — mirror that ambiguity via a plain
    str here since the technique's `hasattr(state, "value")` guard handles
    both.
    """
    sub = MagicMock()
    sub.subscription_id = sub_id
    sub.display_name = display_name
    sub.state = state
    return sub


_SAMPLE_SUBS = [
    _make_sdk_sub("sub-1111", "Production", "Enabled"),
    _make_sdk_sub("sub-2222", "Dev", "Enabled"),
    _make_sdk_sub("sub-3333", "Old", "Disabled"),
]


def _build_ctx(provider_name: str = "azure") -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = MagicMock()
    ctx.provider_name = provider_name
    ctx.whoami.return_value = MagicMock(tenant_id="tenant-abc")
    return ctx


def _run(subs: list | None = None, ctx: MagicMock | None = None) -> dict:
    ctx = ctx if ctx is not None else _build_ctx()
    sub_list = subs if subs is not None else _SAMPLE_SUBS

    with patch("azure.mgmt.subscription.SubscriptionClient") as mock_sub_client:
        mock_sub_client.return_value.subscriptions.list.return_value = sub_list
        return execute(ctx)


class TestSuccessPath:
    def test_returns_subscriptions(self):
        result = _run()
        assert "error" not in result
        assert result["total"] == 3
        assert len(result["subscriptions"]) == 3

    def test_enabled_count(self):
        result = _run()
        assert result["enabled_count"] == 2

    def test_tenant_id_in_result(self):
        result = _run()
        assert result["tenant_id"] == "tenant-abc"

    def test_provider_field_reflects_azure(self):
        """Proves the fix: an 'azure'-provider credential can run this technique
        and the returned provider field reflects the actual active provider,
        not a hardcoded 'entra'."""
        ctx = _build_ctx(provider_name="azure")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["provider"] == "azure"

    def test_provider_field_reflects_entra_bridge(self):
        """The same technique also succeeds when reached via the entra→azure
        bridge (ctx.provider_name == 'entra', ctx.session already resolved to
        a TokenCredential-compatible object by the runner)."""
        ctx = _build_ctx(provider_name="entra")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["provider"] == "entra"

    def test_empty_subscriptions(self):
        result = _run(subs=[])
        assert result["total"] == 0
        assert result["enabled_count"] == 0
        assert result["subscriptions"] == []

    def test_all_disabled(self):
        disabled = [_make_sdk_sub("x", "X", "Disabled")]
        result = _run(subs=disabled)
        assert result["enabled_count"] == 0

    def test_subscription_fields_preserved(self):
        result = _run()
        first = result["subscriptions"][0]
        assert first["subscriptionId"] == "sub-1111"
        assert first["displayName"] == "Production"
        assert first["state"] == "Enabled"
        assert first["tenantId"] == "tenant-abc"

    def test_state_enum_value_extracted(self):
        """The SDK may return `state` as an enum-like object exposing `.value`
        (SubscriptionState.enabled) rather than a plain string — the technique
        must normalize it to the plain string the formatter/loot schema expect."""
        enum_state = MagicMock()
        enum_state.value = "Enabled"
        sub = _make_sdk_sub("sub-enum", "EnumSub", "placeholder")
        sub.state = enum_state
        result = _run(subs=[sub])
        assert result["subscriptions"][0]["state"] == "Enabled"
        assert result["enabled_count"] == 1


class TestMixedStates:
    def test_counts_only_enabled(self):
        subs = [
            _make_sdk_sub("a", "A", "Enabled"),
            _make_sdk_sub("b", "B", "Warned"),
            _make_sdk_sub("c", "C", "PastDue"),
            _make_sdk_sub("d", "D", "Disabled"),
            _make_sdk_sub("e", "E", "Enabled"),
        ]
        result = _run(subs=subs)
        assert result["enabled_count"] == 2
        assert result["total"] == 5

    def test_missing_state_not_counted_as_enabled(self):
        subs = [_make_sdk_sub("a", "A", None)]
        result = _run(subs=subs)
        assert result["enabled_count"] == 0
        assert result["subscriptions"][0]["state"] is None


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
        assert result["subscriptions"] == []

    def test_whoami_failure_does_not_abort_execution(self):
        """If tenant_id resolution via ctx.whoami() fails, subscriptions should
        still be returned with tenant_id omitted/None rather than the whole
        technique erroring out."""
        ctx = _build_ctx()
        ctx.whoami.side_effect = Exception("whoami failed")
        result = _run(ctx=ctx)
        assert "error" not in result
        assert result["tenant_id"] is None
        assert result["total"] == 3
