"""Tests for the `help` command — both bare and per-command forms."""
from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands import cmd_help


def _make_state():
    state = MagicMock()
    state.loader.get.return_value = None
    return state


def test_help_no_args_lists_commands_from_registry():
    """OUTCOME: bare `help` prints all commands grouped by category."""
    state = _make_state()
    with patch("quantum_mechanic.shell.formatters.format_help_menu") as mock_menu:
        cmd_help(state, [])
    mock_menu.assert_called_once()


def test_help_shell_command_shows_record():
    """OUTCOME: `help creds` resolves the shell command, prints its CommandHelp."""
    state = _make_state()
    with patch("quantum_mechanic.shell.commands.console") as mock_console:
        cmd_help(state, ["creds"])
    # Console should have been printed-to (full record renders multiple lines)
    assert mock_console.print.call_count > 0
    # The technique loader must NOT have been consulted for a shell command
    state.loader.get.assert_not_called()


def test_help_unknown_falls_through_to_technique_lookup():
    """OUTCOME: `help discovery/whoami` calls the technique loader."""
    state = _make_state()
    state.loader.get.return_value = MagicMock()
    state.loader.get.return_value.metadata = MagicMock(
        id="discovery/whoami",
        description="x",
        tactic="discovery",
        mitre_id="T1087.004",
        providers=["aws"],
        severity="info",
        safe=True,
        parameters=[],
    )
    state.loader.get.return_value.module_path = "quantum_mechanic.techniques.discovery.whoami"
    with patch("quantum_mechanic.shell.commands.console"):
        cmd_help(state, ["discovery/whoami"])
    state.loader.get.assert_called_with("discovery/whoami")


def test_help_unknown_name_shows_error():
    """OUTCOME: `help nonexistent` prints a clear error (not silent)."""
    state = _make_state()
    state.loader.get.return_value = None
    with patch("quantum_mechanic.shell.commands.console") as mock_console:
        cmd_help(state, ["nonexistent"])
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "not found" in printed.lower() or "neither" in printed.lower()
