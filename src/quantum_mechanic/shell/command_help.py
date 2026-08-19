"""CommandHelp dataclass + registry helpers for shell-command help.

Each shell command (cmd_creds, cmd_workspace, etc.) declares a CommandHelp
record that drives both in-shell `help` output and the auto-generated
docs/wiki/Commands.md page. Single source of truth, two renderers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The documented categories for the help menu. Keep this short and stable —
# the wiki page section structure mirrors it.
VALID_CATEGORIES = {
    "workspaces",
    "credentials",
    "techniques",
    "playbooks",
    "evidence",
    "reporting",
    "shell",
    "advanced",
}


@dataclass(frozen=True)
class SubcommandHelp:
    """A single subcommand entry under a top-level command.

    Example: `creds delete <id>` is SubcommandHelp(name="delete", args="<id>").
    """

    name: str
    synopsis: str
    args: str = ""
    example: str | None = None


@dataclass(frozen=True)
class FlagHelp:
    """A flag/option for a command.

    Example: `--provider aws` is FlagHelp(name="--provider", value="<name>",
    synopsis="Filter by provider").
    """

    name: str
    synopsis: str
    value: str = ""


@dataclass
class CommandHelp:
    """Structured help record for a shell command."""

    name: str
    category: str
    synopsis: str
    description: str
    subcommands: list[SubcommandHelp] = field(default_factory=list)
    flags: list[FlagHelp] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.synopsis:
            raise ValueError(f"CommandHelp({self.name!r}) requires non-empty synopsis")
        if self.category not in VALID_CATEGORIES:
            raise ValueError(
                f"CommandHelp({self.name!r}) category={self.category!r} not in "
                f"valid set {sorted(VALID_CATEGORIES)}"
            )
