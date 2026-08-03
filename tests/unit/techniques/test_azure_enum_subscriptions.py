# ================================================================
# TESTS: techniques/discovery/azure_enum_subscriptions
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.token_store import ARM, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.azure_enum_subscriptions import execute

_SAMPLE_SUBS = [
    {
        "subscriptionId": "sub-1111",
        "displayName": "Production",
        "state": "Enabled",
        "tenantId": "tenant-abc",
        "authorizationSource": "RoleBased",
    },
    {
        "subscriptionId": "sub-2222",
        "displayName": "Dev",
        "state": "Enabled",
        "tenantId": "tenant-abc",
        "authorizationSource": "RoleBased",
    },
    {
        "subscriptionId": "sub-3333",
        "displayName": "Old",
        "state": "Disabled",
        "tenantId": "tenant-abc",
        "authorizationSource": "RoleBased",
    },
]


def _make_store(token: EntraToken) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-abc")
    store.add_token(token)
    return store


def _make_access_token(resource: str = ARM) -> EntraToken:
    return EntraToken(
        token_type="access_token",
        resource=resource,
        value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0ZW5hbnQtYWJjIn0.sig",
        tenant_id="tenant-abc",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=False,
    )


def _make_foci_token() -> EntraToken:
    return EntraToken(
        token_type="refresh_token",
        resource="",
        value="foci-refresh-token-value",
        tenant_id="tenant-abc",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=True,
    )


def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = store
    return ctx


def _mock_http(subs: list[dict]) -> MagicMock:
    http = MagicMock()
    http.__enter__ = lambda s: http
    http.__exit__ = MagicMock(return_value=False)
    return http


def _run(subs: list[dict] | None = None, foci: bool = False) -> dict:
    if foci:
        store = _make_store(_make_foci_token())
    else:
        store = _make_store(_make_access_token())
    ctx = _build_ctx(store)
    sub_list = subs if subs is not None else _SAMPLE_SUBS
    http_mock = _mock_http(sub_list)

    with patch(
        "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.arm_list",
        return_value=sub_list,
    ), patch(
        "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.httpx.Client",
        return_value=http_mock,
    ):
        return execute(ctx)


class TestNoToken:
    def test_returns_error_when_no_token(self):
        store = EntraTokenStore(tenant_id="tenant-abc")
        ctx = _build_ctx(store)
        result = execute(ctx)
        assert "error" in result
        assert "ARM" in result["error"]

    def test_returns_error_when_foci_expand_fails(self):
        store = _make_store(_make_foci_token())
        ctx = _build_ctx(store)
        http_mock = MagicMock()
        http_mock.__enter__ = lambda s: http_mock
        http_mock.__exit__ = MagicMock(return_value=False)
        with patch(
            "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.foci_expand",
            return_value=None,
        ):
            result = execute(ctx)
        assert "error" in result
        assert "FOCI" in result["error"]


class TestSuccessWithAccessToken:
    def test_returns_subscriptions(self):
        result = _run()
        assert result["total"] == 3
        assert len(result["subscriptions"]) == 3

    def test_enabled_count(self):
        result = _run()
        assert result["enabled_count"] == 2

    def test_tenant_id_in_result(self):
        result = _run()
        assert result["tenant_id"] == "tenant-abc"

    def test_provider_field(self):
        result = _run()
        assert result["provider"] == "entra"

    def test_empty_subscriptions(self):
        result = _run(subs=[])
        assert result["total"] == 0
        assert result["enabled_count"] == 0
        assert result["subscriptions"] == []

    def test_all_disabled(self):
        disabled = [{"subscriptionId": "x", "state": "Disabled"}]
        result = _run(subs=disabled)
        assert result["enabled_count"] == 0

    def test_subscription_fields_preserved(self):
        result = _run()
        first = result["subscriptions"][0]
        assert first["subscriptionId"] == "sub-1111"
        assert first["displayName"] == "Production"
        assert first["state"] == "Enabled"


class TestFociExpansion:
    def test_foci_token_triggers_expand(self):
        store = _make_store(_make_foci_token())
        ctx = _build_ctx(store)
        http_mock = MagicMock()
        http_mock.__enter__ = lambda s: http_mock
        http_mock.__exit__ = MagicMock(return_value=False)
        expanded = _make_access_token(ARM)

        with patch(
            "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.foci_expand",
            return_value=expanded,
        ) as mock_expand, patch(
            "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.arm_list",
            return_value=_SAMPLE_SUBS,
        ), patch(
            "quantum_mechanic.techniques.discovery.azure_enum_subscriptions.httpx.Client",
            return_value=http_mock,
        ):
            result = execute(ctx)

        mock_expand.assert_called_once_with(store, ARM)
        assert result["total"] == 3

    def test_result_uses_expanded_token(self):
        result = _run(foci=True)
        # With patched arm_list, result should still be correct
        assert "total" in result


class TestMixedStates:
    def test_counts_only_enabled(self):
        subs = [
            {"subscriptionId": "a", "state": "Enabled"},
            {"subscriptionId": "b", "state": "Warned"},
            {"subscriptionId": "c", "state": "PastDue"},
            {"subscriptionId": "d", "state": "Disabled"},
            {"subscriptionId": "e", "state": "Enabled"},
        ]
        result = _run(subs=subs)
        assert result["enabled_count"] == 2
        assert result["total"] == 5

    def test_missing_state_not_counted_as_enabled(self):
        subs = [{"subscriptionId": "a"}]
        result = _run(subs=subs)
        assert result["enabled_count"] == 0
