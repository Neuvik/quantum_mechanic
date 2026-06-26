"""Tests for entra_enum_group_members --transitive parameter."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import EntraToken, EntraTokenStore, GRAPH
from quantum_mechanic.techniques.discovery.entra_enum_group_members import execute


def _make_store():
    store = EntraTokenStore(tenant_id="t1", user_upn="alice@contoso.com")
    store.add_token(EntraToken(
        token_type="access_token",
        value="eyJ.fake",
        resource=GRAPH,
        tenant_id="t1",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    ))
    return store


def _build_ctx(store, params: dict | None = None):
    ctx = MagicMock()
    ctx.session = store
    ctx.provider_name = "entra"
    p = params or {}
    ctx.get_param.side_effect = lambda k: p.get(k)
    return ctx


def _patched_run(ctx, captured_urls):
    """Run the technique with graph_list capturing URLs and httpx returning an empty group."""
    def capture(http, url, headers, **kw):
        captured_urls.append(url)
        return []

    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_group_members.graph_list",
        side_effect=capture,
    ), patch(
        "quantum_mechanic.techniques.discovery.entra_enum_group_members.httpx.Client",
    ) as mock_httpx:
        mock_http = MagicMock()
        mock_http.__enter__.return_value = mock_http
        mock_http.get.return_value = MagicMock(
            status_code=200, json=lambda: {"displayName": "G1"}
        )
        mock_httpx.return_value = mock_http
        execute(ctx)


def test_default_uses_direct_members_endpoint():
    """OUTCOME: Without --transitive, the technique calls /groups/{id}/members."""
    captured = []
    _patched_run(_build_ctx(_make_store(), {"group_id": "g1"}), captured)
    assert any("/groups/g1/members" in u and "transitiveMembers" not in u for u in captured), (
        f"Expected /groups/g1/members in captured URLs, got: {captured}"
    )


def test_transitive_uses_transitive_members_endpoint():
    """OUTCOME: --transitive=True swaps to /groups/{id}/transitiveMembers."""
    captured = []
    _patched_run(_build_ctx(_make_store(), {"group_id": "g1", "transitive": True}), captured)
    assert any("/groups/g1/transitiveMembers" in u for u in captured), (
        f"Expected /groups/g1/transitiveMembers in captured URLs, got: {captured}"
    )


def test_transitive_string_true_also_works():
    """OUTCOME: --transitive=\"true\" (string) is interpreted as True (CLI passes strings)."""
    captured = []
    _patched_run(_build_ctx(_make_store(), {"group_id": "g1", "transitive": "true"}), captured)
    assert any("/groups/g1/transitiveMembers" in u for u in captured), (
        f"Expected /groups/g1/transitiveMembers in captured URLs, got: {captured}"
    )
