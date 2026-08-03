# ================================================================
# TESTS: quantum_mechanic.techniques.escalation.entra_app_add_secret
# ----------------------------------------------------------------
# Guards the merged technique that replaced entra_app_creds and
# entra_app_pivot. Both old techniques made the identical Graph call
# (POST /applications/{id}/addPassword); this file tests the merged
# module + its two operator modes ('own' and 'pivot').
# ================================================================
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.escalation.entra_app_add_secret import execute


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


def _build_ctx(store, object_id="app-obj-123", mode="own", display_name="QM-Added-Secret"):
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "entra"
    ctx.session = store
    params = {"object_id": object_id, "mode": mode, "display_name": display_name}
    ctx.get_param.side_effect = lambda key: params.get(key)
    ctx.log_api_call = MagicMock()
    ctx.info = MagicMock()
    ctx.success = MagicMock()
    ctx.finding = MagicMock()
    return ctx


# ================================================================
# Precondition guards
# ================================================================

def test_no_token_returns_error():
    ctx = _build_ctx(_make_store())
    result = execute(ctx)
    assert result["status"] == "error"
    assert "No Graph token" in result["error"]


def test_foci_expansion_failure_returns_error():
    store = _make_store(_make_token("refresh_token", foci=True))
    ctx = _build_ctx(store)
    with patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret.foci_expand",
        return_value=None,
    ):
        result = execute(ctx)
    assert result["status"] == "error"


def test_invalid_mode_returns_error():
    """OUTCOME: mode must be 'own' or 'pivot'. Anything else is an operator
    error and gets rejected before any Graph call fires."""
    ctx = _build_ctx(_make_store(_make_token()), mode="rogue")
    result = execute(ctx)
    assert result["status"] == "error"
    assert "Invalid mode" in result["error"]


# ================================================================
# Mode: own — self-owned app framing
# ================================================================

def test_mode_own_success_no_finding():
    """OUTCOME: mode=own → success, but NO ctx.finding() call (severity high,
    not critical — you own the app, this is persistence not privesc).
    """
    store = _make_store(_make_token("access_token"))
    ctx = _build_ctx(store, mode="own")

    post_resp = MagicMock(status_code=200)
    post_resp.json.return_value = {"secretText": "own-secret", "keyId": "kid-1"}
    get_resp = MagicMock(status_code=200)
    get_resp.json.return_value = {"appId": "app-client-own"}

    with patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret._graph_call",
        side_effect=[post_resp, get_resp],
    ), patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret.httpx.Client",
        return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
    ):
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["mode"] == "own"
    assert result["app_id"] == "app-client-own"
    assert result["secret_text"] == "own-secret"
    ctx.finding.assert_not_called()
    ctx.success.assert_called_once()


# ================================================================
# Mode: pivot — Application Administrator framing
# ================================================================

def test_mode_pivot_success_emits_critical_finding():
    """OUTCOME: mode=pivot → success PLUS a critical Finding is recorded
    (this is a real escalation event worth reporting)."""
    store = _make_store(_make_token("access_token"))
    ctx = _build_ctx(store, mode="pivot")

    post_resp = MagicMock(status_code=200)
    post_resp.json.return_value = {"secretText": "pivot-secret", "keyId": "kid-2"}
    get_resp = MagicMock(status_code=200)
    get_resp.json.return_value = {"appId": "app-client-victim"}

    with patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret._graph_call",
        side_effect=[post_resp, get_resp],
    ), patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret.httpx.Client",
        return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
    ):
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["mode"] == "pivot"
    assert result["app_id"] == "app-client-victim"

    ctx.finding.assert_called_once()
    _, kwargs = ctx.finding.call_args
    assert "Lateral Movement" in kwargs["title"]
    assert "app-client-victim" in kwargs["title"]
    assert kwargs["severity"] == "critical"


# ================================================================
# Error handling — shared across modes
# ================================================================

def test_403_returns_descriptive_error_with_both_mode_hints():
    """OUTCOME: 403 error message mentions BOTH mode's remediation paths
    (owner check for own, directory-role check for pivot) so operators
    can figure out which precondition they're missing."""
    store = _make_store(_make_token("access_token"))
    ctx = _build_ctx(store, mode="own")

    forbidden = MagicMock(status_code=403)

    with patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret._graph_call",
        return_value=forbidden,
    ), patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret.httpx.Client",
        return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
    ):
        result = execute(ctx)

    assert result["status"] == "error"
    assert "403" in result["error"]
    assert "own" in result["error"].lower()
    assert "pivot" in result["error"].lower()
    ctx.finding.assert_not_called()


def test_500_returns_generic_http_error():
    store = _make_store(_make_token("access_token"))
    ctx = _build_ctx(store, mode="pivot")

    server_err = MagicMock(status_code=500, text="Internal Server Error")
    server_err.json.side_effect = Exception("no json")

    with patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret._graph_call",
        return_value=server_err,
    ), patch(
        "quantum_mechanic.techniques.escalation.entra_app_add_secret.httpx.Client",
        return_value=MagicMock(__enter__=lambda s: s, __exit__=MagicMock()),
    ):
        result = execute(ctx)

    assert result["status"] == "error"
    assert "HTTP 500" in result["error"]
    ctx.finding.assert_not_called()
