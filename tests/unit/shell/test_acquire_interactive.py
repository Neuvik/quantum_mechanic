"""Tests for `acquire entra interactive` shell command."""
from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands_entra import acquire_entra


def test_acquire_entra_interactive_calls_interactive_authorize():
    """OUTCOME: `acquire entra interactive` calls interactive_authorize() and
    persists the resulting tokens via the standard helpers."""
    state = MagicMock()
    state.workspace = MagicMock()
    state.workspace.active_credential_id = None

    fake_token = {
        "access_token": "eyJ.fake.access",
        "refresh_token": "0.fake.refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize",
        return_value=fake_token,
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra._store_from_response"
    ) as mock_store_fn, patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=42,
    ) as mock_persist, patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ), patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        mock_store_fn.return_value = MagicMock()
        acquire_entra(state, ["interactive"])

    mock_authorize.assert_called_once()
    assert mock_authorize.call_args.kwargs["tenant_id"] == "common"
    mock_persist.assert_called_once()


def test_acquire_entra_interactive_propagates_auth_error():
    """OUTCOME: an error from interactive_authorize prints a clear message
    and does NOT call _persist_store."""
    state = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize",
        return_value={"error": "expired_token", "error_description": "timed out"},
    ), patch(
        "quantum_mechanic.shell.commands_entra._persist_store"
    ) as mock_persist, patch(
        "quantum_mechanic.shell.commands_entra.console"
    ) as mock_console:
        acquire_entra(state, ["interactive"])

    mock_persist.assert_not_called()
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "timed out" in printed.lower() or "expired" in printed.lower()


def test_acquire_entra_interactive_respects_tenant_flag():
    """OUTCOME: --tenant <id> overrides the default 'common'."""
    state = MagicMock()
    fake_token = {
        "access_token": "x",
        "refresh_token": "y",
        "expires_in": 1,
        "token_type": "Bearer",
    }

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize",
        return_value=fake_token,
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra._store_from_response"
    ) as mock_store_fn, patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=1,
    ), patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ), patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        mock_store_fn.return_value = MagicMock()
        acquire_entra(state, ["interactive", "--tenant", "contoso.onmicrosoft.com"])

    assert mock_authorize.call_args.kwargs["tenant_id"] == "contoso.onmicrosoft.com"
