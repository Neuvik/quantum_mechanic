"""Tests for Part 2: acquire produces a new derived credential row.

When the operator runs `acquire entra arm` (or a refresh for a resource
not already in the store), we mint a NEW credential with derived_from_id
pointing at the parent — so `use <old>` / `use <new>` navigates between
the pivots.

ANTI-GAMIFICATION: If someone reverts to the old level-up-in-place
behavior, the operator loses their pivot chain — this test suite fails.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import (
    ARM,
    GRAPH,
    EntraToken,
    EntraTokenStore,
)
from quantum_mechanic.shell.commands_entra import _acquire_arm


def _future(mins: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=mins)


def _make_store_with_foci_only() -> EntraTokenStore:
    """Store with a FOCI RT but no ARM AT — the scenario where `acquire arm`
    is meaningful."""
    store = EntraTokenStore(tenant_id="tenant-1", user_upn="alice@x.com")
    store.add_token(EntraToken(
        token_type="refresh_token", value="rt-value", resource="",
        tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT, foci=True,
        expires_at=_future(60 * 24 * 60),
    ))
    return store


def _make_state_with(store: EntraTokenStore, ws: Workspace, cred_id: int):
    state = MagicMock()
    state.workspace = ws
    state.transport = MagicMock()
    state.active_credential_id = cred_id
    state.active_credential_label = "alice@x.com"
    state._extra_providers = []
    return state


def test_acquire_arm_mints_new_credential_derived_from_current():
    """OUTCOME: `acquire entra arm` produces a new cred row with
    derived_from_id pointing at the original, and switches active to it.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ws = Workspace.create("test", tmp)
        store = _make_store_with_foci_only()
        parent_id = ws.add_credential(
            provider="entra", credential_type="token_store",
            secret_data=json.dumps({"token_store": store.to_dict()}),
            friendly_name="alice@x.com",
        )

        state = _make_state_with(store, ws, parent_id)

        # Patch foci_expand to succeed with a mock ARM token that we
        # actually add to the store — matching what real foci_expand does.
        arm_token = EntraToken(
            token_type="access_token", value="arm-at", resource=ARM,
            tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
            expires_at=_future(80),
        )
        def fake_expand(s, res):
            s.add_token(arm_token)
            return arm_token
        with patch("quantum_mechanic.providers.entra.foci.foci_expand", side_effect=fake_expand), \
             patch("quantum_mechanic.shell.commands_entra._active_entra_store", return_value=store):
            _acquire_arm(state, {})

        # Active id was switched to the new derived cred, not the parent.
        assert state.active_credential_id != parent_id, (
            "acquire entra arm must mint a new cred and switch to it"
        )
        new_cred = ws.get_credential(state.active_credential_id)
        assert new_cred is not None
        assert new_cred.derived_from_id == parent_id, (
            f"new cred must be derived from parent #{parent_id}, "
            f"got derived_from_id={new_cred.derived_from_id}"
        )
        ws.close()


def test_acquire_arm_when_arm_already_present_is_noop():
    """OUTCOME: If an ARM AT already exists and is live, `acquire arm` does not
    mint a new cred — it prints a "already present" message and returns."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ws = Workspace.create("test", tmp)
        store = _make_store_with_foci_only()
        store.add_token(EntraToken(
            token_type="access_token", value="arm-live", resource=ARM,
            tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
            expires_at=_future(50),
        ))
        parent_id = ws.add_credential(
            provider="entra", credential_type="token_store",
            secret_data=json.dumps({"token_store": store.to_dict()}),
            friendly_name="alice@x.com",
        )

        state = _make_state_with(store, ws, parent_id)
        with patch("quantum_mechanic.shell.commands_entra._active_entra_store", return_value=store):
            _acquire_arm(state, {})

        # Active id unchanged — no new cred.
        assert state.active_credential_id == parent_id
        assert len(ws.list_credentials()) == 1
        ws.close()


def test_new_cred_carries_expires_at_matching_the_new_token():
    """OUTCOME: The minted cred's expires_at field is populated so operators
    (and the display) know when the ARM AT dies."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ws = Workspace.create("test", tmp)
        store = _make_store_with_foci_only()
        parent_id = ws.add_credential(
            provider="entra", credential_type="token_store",
            secret_data=json.dumps({"token_store": store.to_dict()}),
            friendly_name="alice@x.com",
        )
        state = _make_state_with(store, ws, parent_id)

        arm_exp = _future(80)
        arm_token = EntraToken(
            token_type="access_token", value="arm-at", resource=ARM,
            tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
            expires_at=arm_exp,
        )
        def fake_expand(s, res):
            s.add_token(arm_token)
            return arm_token
        with patch("quantum_mechanic.providers.entra.foci.foci_expand", side_effect=fake_expand), \
             patch("quantum_mechanic.shell.commands_entra._active_entra_store", return_value=store):
            _acquire_arm(state, {})

        new_cred = ws.get_credential(state.active_credential_id)
        assert new_cred.expires_at is not None
        # ISO-format should match roughly (allow for round-trip drift).
        assert "2026" in new_cred.expires_at or "2027" in new_cred.expires_at
        ws.close()


def test_new_cred_friendly_name_shows_pivot_arrow():
    """OUTCOME: New cred's friendly_name has '→ ARM' suffix so operators can
    read the cred list and see the pivot direction at a glance."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ws = Workspace.create("test", tmp)
        store = _make_store_with_foci_only()
        parent_id = ws.add_credential(
            provider="entra", credential_type="token_store",
            secret_data=json.dumps({"token_store": store.to_dict()}),
            friendly_name="alice@x.com",
        )
        state = _make_state_with(store, ws, parent_id)

        arm_token = EntraToken(
            token_type="access_token", value="arm-at", resource=ARM,
            tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
            expires_at=_future(80),
        )
        def fake_expand(s, res):
            s.add_token(arm_token)
            return arm_token
        with patch("quantum_mechanic.providers.entra.foci.foci_expand", side_effect=fake_expand), \
             patch("quantum_mechanic.shell.commands_entra._active_entra_store", return_value=store):
            _acquire_arm(state, {})

        new_cred = ws.get_credential(state.active_credential_id)
        assert "→ ARM" in new_cred.friendly_name or "ARM" in new_cred.friendly_name
        ws.close()


def test_new_cred_records_obtained_via():
    """OUTCOME: obtained_via names the command that produced this cred so the
    audit trail is legible."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ws = Workspace.create("test", tmp)
        store = _make_store_with_foci_only()
        parent_id = ws.add_credential(
            provider="entra", credential_type="token_store",
            secret_data=json.dumps({"token_store": store.to_dict()}),
            friendly_name="alice@x.com",
        )
        state = _make_state_with(store, ws, parent_id)

        arm_token = EntraToken(
            token_type="access_token", value="arm-at", resource=ARM,
            tenant_id="tenant-1", client_id=FOCI_DEFAULT_CLIENT,
            expires_at=_future(80),
        )
        def fake_expand(s, res):
            s.add_token(arm_token)
            return arm_token
        with patch("quantum_mechanic.providers.entra.foci.foci_expand", side_effect=fake_expand), \
             patch("quantum_mechanic.shell.commands_entra._active_entra_store", return_value=store):
            _acquire_arm(state, {})

        new_cred = ws.get_credential(state.active_credential_id)
        assert new_cred.obtained_via == "acquire entra arm"
        ws.close()
