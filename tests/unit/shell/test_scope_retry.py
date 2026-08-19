"""Tests for the semi-automatic FOCI scope retry (Task #3).

Guards `_maybe_offer_scope_retry`:
- denied + required_scope + entra + FOCI RT + operator says yes → retry
- operator says no → no retry, original denied preserved
- non-denied result → no retry
- denied without required_scope → no retry
- active cred is not entra → no retry
- entra cred but no FOCI RT → no retry
- FOCI expansion returns consent_required → no retry, honest error
- EOF/KeyboardInterrupt at prompt → no retry
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.runner import TechniqueResult
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import (
    EntraToken,
    EntraTokenStore,
)
from quantum_mechanic.providers.entra.scope_exchange import ScopeExchangeResult
from quantum_mechanic.shell.commands import _maybe_offer_scope_retry


def _future(mins: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=mins)


def _store_with_foci() -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-1", user_upn="alice@x.example")
    store.add_token(EntraToken(
        token_type="refresh_token", value="rt", resource="",
        tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT, foci=True,
        expires_at=_future(60 * 24 * 60),
    ))
    return store


def _state_with_entra_cred(ws: Workspace, store: EntraTokenStore) -> MagicMock:
    cred_id = ws.add_credential(
        provider="entra",
        credential_type="token_store",
        secret_data=json.dumps({"token_store": store.to_dict()}),
        friendly_name="alice@x.example",
    )
    state = MagicMock()
    state.workspace = ws
    state.active_credential_id = cred_id
    state._extra_providers = []
    state.transport = MagicMock()
    state.transport.list_credentials.return_value = [{
        "id": cred_id, "provider": "entra", "credential_type": "token_store",
        "friendly_name": "alice@x.example", "status": "active",
    }]
    return state


def _denied_result(scope: str = "User.Read.All") -> TechniqueResult:
    return TechniqueResult(
        technique_id="discovery/entra_enum_users",
        provider="entra",
        status="denied",
        data={
            "error": "HTTP 403",
            "required_scope": scope,
            "http_status": 403,
        },
        error="HTTP 403",
    )


def test_no_retry_when_result_is_not_denied():
    """OUTCOME: A success result → no prompt, no retry."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())
        good = TechniqueResult(
            technique_id="x", provider="entra", status="success",
            data={"items": [1]},
        )
        assert _maybe_offer_scope_retry(state, good, "x", {}) is None


def test_no_retry_when_denied_lacks_required_scope():
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())
        denied = TechniqueResult(
            technique_id="x", provider="entra", status="denied",
            data={"error": "HTTP 403"},  # no required_scope
            error="HTTP 403",
        )
        assert _maybe_offer_scope_retry(state, denied, "x", {}) is None


def test_no_retry_when_active_cred_is_not_entra():
    """OUTCOME: AWS active cred → no retry even if the result looked scope-shaped
    (should never happen but guard against it)."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="aws", credential_type="access_key",
            secret_data=json.dumps({"profile_name": "x"}),
            friendly_name="profile:x",
        )
        state = MagicMock()
        state.workspace = ws
        state.active_credential_id = cred_id
        state.transport = MagicMock()
        state.transport.list_credentials.return_value = [{
            "id": cred_id, "provider": "aws", "credential_type": "access_key",
            "friendly_name": "profile:x", "status": "active",
        }]
        assert _maybe_offer_scope_retry(state, _denied_result(), "x", {}) is None


def test_no_retry_when_entra_store_has_no_foci_rt():
    """OUTCOME: Entra cred but no FOCI RT → no prompt, no retry."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        # Store without a FOCI RT.
        empty_store = EntraTokenStore(tenant_id="t", user_upn="x@y.example")
        state = _state_with_entra_cred(ws, empty_store)
        assert _maybe_offer_scope_retry(state, _denied_result(), "x", {}) is None


def test_operator_declines_prompt_returns_none():
    """OUTCOME: Confirm.ask returns False → no retry."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())
        with patch("rich.prompt.Confirm.ask", return_value=False):
            assert _maybe_offer_scope_retry(state, _denied_result(), "x", {}) is None


def test_eof_or_keyboard_interrupt_at_prompt_returns_none():
    """OUTCOME: EOFError or Ctrl-C during prompt is treated as decline."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())
        with patch("rich.prompt.Confirm.ask", side_effect=EOFError()):
            assert _maybe_offer_scope_retry(state, _denied_result(), "x", {}) is None
        with patch("rich.prompt.Confirm.ask", side_effect=KeyboardInterrupt()):
            assert _maybe_offer_scope_retry(state, _denied_result(), "x", {}) is None


def test_operator_says_yes_and_expansion_grants_triggers_rerun():
    """OUTCOME: Yes → try_acquire_scope grants → run_technique invoked again
    with auto_scope=False, result of retry returned to caller."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())

        # Fresh technique result to return from re-run.
        retry_result = TechniqueResult(
            technique_id="x", provider="entra", status="success",
            data={"items": [1, 2]},
        )
        state.transport.run_technique.return_value = retry_result

        # Stub try_acquire_scope to return granted.
        granted = ScopeExchangeResult(
            status="granted",
            token=EntraToken(
                token_type="access_token", value="new-at",
                resource="https://graph.microsoft.com",
                tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
                expires_at=_future(50),
            ),
        )
        with patch("rich.prompt.Confirm.ask", return_value=True), \
             patch(
                 "quantum_mechanic.providers.entra.scope_exchange.try_acquire_scope",
                 return_value=granted,
             ):
            out = _maybe_offer_scope_retry(state, _denied_result(), "x", {})

        assert out is retry_result, "retry result must propagate back"
        # And the retry call MUST disable auto_scope to prevent infinite chains.
        _, kwargs = state.transport.run_technique.call_args
        assert kwargs.get("auto_scope") is False


def test_yes_but_expansion_returns_consent_required_no_rerun():
    """OUTCOME: Operator agrees but AAD says consent_required → no rerun,
    original denied preserved. Honest failure, not a lie."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("t", workspace_dir=Path(td))
        state = _state_with_entra_cred(ws, _store_with_foci())

        blocked = ScopeExchangeResult(
            status="consent_required", token=None,
            last_error="AADSTS65001",
        )
        with patch("rich.prompt.Confirm.ask", return_value=True), \
             patch(
                 "quantum_mechanic.providers.entra.scope_exchange.try_acquire_scope",
                 return_value=blocked,
             ):
            out = _maybe_offer_scope_retry(state, _denied_result(), "x", {})

        assert out is None
        state.transport.run_technique.assert_not_called()
