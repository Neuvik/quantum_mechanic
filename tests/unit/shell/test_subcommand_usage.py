"""Tests for unknown-subcommand UX."""
from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands import cmd_creds


def test_creds_unknown_subcommand_prints_suggestion():
    """OUTCOME: `creds rm 2` prints 'Did you mean: delete?' and does NOT list."""
    state = MagicMock()
    state.transport = MagicMock()
    state.transport.list_credentials.return_value = []
    state.transport.delete_credential.return_value = False

    with patch("quantum_mechanic.shell.commands.console") as mock_console:
        cmd_creds(state, ["rm", "2"])

    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "rm" in printed
    assert "delete" in printed.lower()
    state.transport.delete_credential.assert_not_called()


def test_creds_no_args_still_lists():
    """OUTCOME: Bare `creds` continues to list (back-compat)."""
    state = MagicMock()
    state.transport = MagicMock()
    state.transport.list_credentials.return_value = []
    state.workspace = None
    with patch("quantum_mechanic.shell.commands.console"):
        cmd_creds(state, [])
    state.transport.list_credentials.assert_called()


def test_creds_valid_subcommand_works():
    """OUTCOME: `creds delete 2` still works."""
    state = MagicMock()
    state.transport = MagicMock()
    state.transport.delete_credential.return_value = True
    state.active_credential_id = 1
    with patch("quantum_mechanic.shell.commands.console"):
        cmd_creds(state, ["delete", "2"])
    state.transport.delete_credential.assert_called_with(2)
