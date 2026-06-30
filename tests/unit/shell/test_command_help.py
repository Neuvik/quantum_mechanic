"""Tests for CommandHelp dataclass and registry helpers."""
import pytest

from quantum_mechanic.shell.command_help import CommandHelp, SubcommandHelp


def test_command_help_minimal_fields():
    """OUTCOME: CommandHelp accepts the minimum set of fields and exposes them."""
    h = CommandHelp(
        name="creds",
        category="credentials",
        synopsis="List or manage workspace credentials",
        description="The creds command operates on the credential store.",
    )
    assert h.name == "creds"
    assert h.category == "credentials"
    assert h.synopsis == "List or manage workspace credentials"
    assert h.subcommands == []
    assert h.examples == []
    assert h.flags == []


def test_command_help_with_subcommands():
    """OUTCOME: subcommands populate as SubcommandHelp records."""
    h = CommandHelp(
        name="creds",
        category="credentials",
        synopsis="List or manage credentials",
        description="...",
        subcommands=[
            SubcommandHelp(name="delete", synopsis="Remove a credential", args="<id>"),
        ],
    )
    assert len(h.subcommands) == 1
    assert h.subcommands[0].name == "delete"
    assert h.subcommands[0].args == "<id>"


def test_subcommand_help_fields():
    """OUTCOME: SubcommandHelp has name, synopsis, args, optional example."""
    s = SubcommandHelp(
        name="delete",
        synopsis="Remove a credential by ID",
        args="<id>",
        example="creds delete 2",
    )
    assert s.example == "creds delete 2"


def test_command_help_requires_synopsis():
    """OUTCOME: synopsis is required; an empty string raises at construction."""
    with pytest.raises(ValueError, match="synopsis"):
        CommandHelp(name="x", category="other", synopsis="", description="...")


def test_command_help_categories_constrained():
    """OUTCOME: category must be one of the documented set."""
    with pytest.raises(ValueError, match="category"):
        CommandHelp(
            name="x", category="invalid-category-xyz",
            synopsis="x", description="y",
        )
