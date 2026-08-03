# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_users
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_users import execute


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
    return ctx


_SAMPLE_USERS = [
    {
        "id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com",
        "accountEnabled": True, "userType": "Member",
    },
    {
        "id": "u2", "displayName": "Bob Guest", "userPrincipalName": "bob_ext#EXT#@contoso.com",
        "accountEnabled": True, "userType": "Guest",
    },
    {
        "id": "u3", "displayName": "Ex-Employee", "userPrincipalName": "ex@contoso.com",
        "accountEnabled": False, "userType": "Member",
    },
]


def _mock_graph_list(return_value: list) -> MagicMock:
    return patch(
        "quantum_mechanic.techniques.discovery.entra_enum_users.graph_list",
        return_value=return_value,
    )


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
        with patch("quantum_mechanic.techniques.discovery.entra_enum_users.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result

    def test_uses_expanded_token(self):
        store = _make_store(_make_token("refresh_token", foci=True))
        ctx = _build_ctx(store)
        expanded = _make_token("access_token")
        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_users.foci_expand",
            return_value=expanded,
        ), _mock_graph_list(_SAMPLE_USERS), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_users.httpx.Client",
            return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
        ):
            result = execute(ctx)
        assert result["total"] == 3


class TestEnumUsers:
    def _run(self, users: list = _SAMPLE_USERS):
        store = _make_store(_make_token())
        ctx = _build_ctx(store)
        http_mock = MagicMock()
        http_mock.__enter__ = lambda s: http_mock
        http_mock.__exit__ = MagicMock(return_value=False)
        with patch(
            "quantum_mechanic.techniques.discovery.entra_enum_users.graph_list",
            return_value=users,
        ), patch(
            "quantum_mechanic.techniques.discovery.entra_enum_users.httpx.Client",
            return_value=http_mock,
        ):
            return execute(ctx)

    def test_total_count(self):
        result = self._run()
        assert result["total"] == 3

    def test_guest_count(self):
        result = self._run()
        assert result["guests"] == 1

    def test_disabled_count(self):
        result = self._run()
        assert result["disabled"] == 1

    def test_users_list_present(self):
        result = self._run()
        assert len(result["users"]) == 3

    def test_tenant_id_in_result(self):
        result = self._run()
        assert result["tenant_id"] == "t"

    def test_provider_in_result(self):
        result = self._run()
        assert result["provider"] == "entra"

    def test_empty_tenant(self):
        result = self._run(users=[])
        assert result["total"] == 0
        assert result["guests"] == 0
        assert result["disabled"] == 0
