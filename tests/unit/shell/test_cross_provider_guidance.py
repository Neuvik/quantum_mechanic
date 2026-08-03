"""Tests for the cross-provider guidance in `acquire entra <*>`.

Real engagement session: operator had an expired `import azure --default`
captured token active. `acquire entra refresh` returned a generic
"No active entra credential" — technically true but useless, because
the operator's actual problem was that a captured Azure token has no
refresh material at all. The fix distinguishes the case and points at
the specific fresh-auth flow.

ANTI-GAMIFICATION: if the guidance ever regresses to a bare "No active
entra credential" one-liner, these tests fail.
"""
from __future__ import annotations

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

from rich.console import Console

from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.shell import commands_entra as ce


def _make_state(workspace: Workspace | None, active_id: int | None = None) -> MagicMock:
    state = MagicMock()
    state.workspace = workspace
    state.transport = MagicMock() if workspace else None
    state.active_credential_id = active_id
    state.active_credential_label = None
    state._extra_providers = []
    return state


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        fn(*args, **kwargs)
    finally:
        ce.console = orig
    return buf.getvalue()


def test_guidance_when_no_workspace_at_all():
    """OUTCOME: With no workspace, guidance names the fresh-auth subcommands."""
    state = _make_state(None)
    out = _capture(ce._print_no_entra_cred_guidance, state, "refresh")
    assert "acquire entra device_code" in out
    assert "acquire entra interactive" in out
    assert "acquire entra ropc" in out


def test_guidance_when_active_cred_is_azure_captured_token():
    """OUTCOME: An expired-or-live `azure/captured_token` active cred triggers
    the specific "captured Azure tokens are audience-bound snapshots" guidance,
    NOT the generic 'no entra cred' line.
    """
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="azure",
            credential_type="captured_token",
            secret_data=json.dumps({
                "method": "captured_token",
                "access_token": "fake",
                "expires_on": 9999999999,
                "captured_principal": "alice@example.com",
            }),
            friendly_name="alice@example.com",
        )
        state = _make_state(ws, active_id=cred_id)
        out = _capture(ce._print_no_entra_cred_guidance, state, "refresh")
        assert "captured Azure" in out or "audience-bound" in out
        assert "acquire entra device_code" in out
        assert "graph.microsoft.com" in out.lower() or "Graph" in out
        ws.close()


def test_guidance_when_active_cred_is_aws():
    """OUTCOME: An AWS active cred gets a distinct message — not the
    captured-Azure-specific one."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "test"}),
            friendly_name="profile:test",
        )
        state = _make_state(ws, active_id=cred_id)
        out = _capture(ce._print_no_entra_cred_guidance, state, "refresh")
        assert "AWS" in out
        assert "acquire entra device_code" in out
        # Must NOT falsely accuse the AWS cred of being a captured Azure token.
        assert "captured Azure" not in out


def test_guidance_when_workspace_but_no_active_cred():
    """OUTCOME: Workspace loaded but no active cred → 'first get one' message."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test", workspace_dir=Path(td))
        state = _make_state(ws, active_id=None)
        out = _capture(ce._print_no_entra_cred_guidance, state, "arm")
        assert "acquire entra device_code" in out
        ws.close()


def test_expired_captured_token_error_names_alternatives():
    """OUTCOME: The expired-captured-token error message points operators at
    the entra device_code / interactive / ropc flows (not just 're-import')."""
    import time
    from quantum_mechanic.providers.azure.static_token import StaticTokenCredential

    stale = StaticTokenCredential(access_token="fake", expires_on=int(time.time()) - 60)
    try:
        stale.get_token("https://management.azure.com/.default")
    except RuntimeError as e:
        msg = str(e)
        assert "captured tokens" in msg.lower() or "captured Azure" in msg
        assert "acquire entra" in msg, (
            "expired captured-token error must point at the entra fresh-auth flows"
        )
    else:
        raise AssertionError("StaticTokenCredential must raise when expired")
