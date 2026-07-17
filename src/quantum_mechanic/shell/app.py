# ================================================================
# MODULE: quantum_mechanic.shell.app
# ----------------------------------------------------------------
# PURPOSE:   Interactive shell using prompt_toolkit. Metasploit-
#            grade command line with tab completion, history,
#            and context-aware prompts.
#
# DESIGN:    The shell is one of three interaction modes:
#            - Interactive (this module) — human at the terminal
#            - Agent mode — JSON on stdout for AI consumption
#            - Guided mode (future) — step-by-step with approval
# ================================================================

from __future__ import annotations

import argparse
import logging
import logging.handlers
import shlex
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.azure.auth import AzureAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.providers.entra.auth import EntraAuthProvider
from quantum_mechanic.providers.gcp.auth import GCPAuthProvider
from quantum_mechanic.providers.oci.auth import OCIAuthProvider
from quantum_mechanic.shell import formatters
from quantum_mechanic.shell.commands import COMMAND_HELP, COMMANDS, ShellState

# Load private commands (exploits, payloads, connect, disconnect) if available.
# In the public build commands_private.py does not exist — the import fails
# silently and the public shell starts without those commands.
try:
    from quantum_mechanic.shell.commands_private import (
        PRIVATE_COMMAND_HELP,
        PRIVATE_COMMANDS,
    )
    COMMANDS.update(PRIVATE_COMMANDS)
    COMMAND_HELP.update(PRIVATE_COMMAND_HELP)
except ImportError:
    pass

logger = logging.getLogger(__name__)


def _build_registry() -> ProviderRegistry:
    """Build the provider registry with available providers."""
    registry = ProviderRegistry()
    registry.register(AWSAuthProvider())
    registry.register(AzureAuthProvider())
    registry.register(EntraAuthProvider())
    registry.register(GCPAuthProvider())
    registry.register(OCIAuthProvider())
    return registry


def _build_completer(state: ShellState) -> NestedCompleter:
    """Build a context-aware tab completer.

    Uses NestedCompleter so completions are scoped per-command.
    Typing 'workspace <TAB>' only shows workspace subcommands,
    not every word in the shell vocabulary.
    """
    # --------------------------------------------------------
    # Technique IDs — shared wherever a technique ID is expected.
    # --------------------------------------------------------
    technique_ids: dict = {t.metadata.id: None for t in state.loader.list_all()}
    exploit_ids: dict = {t.metadata.id: None for t in state.loader.list_exploits()}

    # --------------------------------------------------------
    # Nested command completion tree.
    # None means the value accepts free-form input (no further suggestions).
    # --------------------------------------------------------
    completions: dict = {
        # ── Workspaces ─────────────────────────────────────────
        "workspace": {
            "create": None,
            "load": None,
            "list": None,
        },
        # ── Credentials ─────────────────────────────────────────
        "creds": {
            "delete": None,
        },
        "use": None,
        # ── Import ──────────────────────────────────────────────
        "import": {
            "aws": {
                "--profile": None,
                "--access-key": None,
                "--secret-key": None,
                "--session-token": None,
                "--region": None,
            },
            "azure": {
                "--default": None,
                "--client-id": None,
                "--client-secret": None,
                "--tenant-id": None,
            },
            "gcp": {
                "--default": None,
                "--key-file": None,
            },
            "oci": {
                "--profile": None,
                "--config-file": None,
            },
        },
        # ── Techniques ──────────────────────────────────────────
        "techniques": None,
        "run": technique_ids,
        "reload": None,
        # ── Technique info / help ───────────────────────────────
        "info": technique_ids,
        "help": technique_ids,
        # ── Reporting / Evidence ────────────────────────────────
        "report": None,
        "raw": None,
        # ── Agent ───────────────────────────────────────────────
        "ask": None,
        # ── Session ─────────────────────────────────────────────
        "exit": None,
        "quit": None,
    }

    # ── Conditional Private Commands (Public Hygiene) ──────────────
    if "exploits" in COMMANDS:
        completions["exploits"] = {
            "list": None,
            "run": exploit_ids,
        }
    if "payloads" in COMMANDS:
        completions["payloads"] = {
            "list": None,
            "generate": {
                "--wrapper": {"bash": None, "python": None, "raw": None},
                "--no-minify": None,
            },
            "info": None,
        }
    if "connect" in COMMANDS:
        completions["connect"] = None
    if "disconnect" in COMMANDS:
        completions["disconnect"] = None

    return NestedCompleter.from_nested_dict(completions)


def run_shell(args: argparse.Namespace) -> None:
    """Launch the interactive QM shell."""
    # --------------------------------------------------------
    # Setup logging — split between minimal console and verbose file
    # --------------------------------------------------------
    log_dir = Path.home() / ".quantum_mechanic" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Minimal console output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    # Verbose file sink
    # Rotating handler — see agent/mode.py for the 252 GB story.
    file_handler = logging.handlers.RotatingFileHandler(
        str(log_dir / "qm.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # --------------------------------------------------------
    # Initialize core components.
    # --------------------------------------------------------
    registry = _build_registry()
    loader = TechniqueLoader()
    technique_count = loader.load_all()

    state = ShellState(
        workspace=None,
        loader=loader,
        registry=registry,
    )

    def _notify_agent_checkin(agent):
        """Callback to notify operator of new agent check-ins."""
        formatters.console.print(
            f"\n[bold green]⚡ agent check-in:[/bold green] "
            f"[bold]{agent.hostname}[/bold] ({agent.internal_ip}) "
            f"ID: [dim]{agent.id[:8]}...[/dim]"
        )

    state.on_agent_update(_notify_agent_checkin)

    # --------------------------------------------------------
    # Load workspace from args if specified.
    # --------------------------------------------------------
    if args.workspace:
        from quantum_mechanic.shell.commands import cmd_workspace

        cmd_workspace(state, ["load", args.workspace])

    # --------------------------------------------------------
    # Display startup banner.
    # --------------------------------------------------------
    formatters.format_banner()
    formatters.console.print(
        f"  [dim]{technique_count} technique(s) loaded. "
        f"Providers: {', '.join(registry.available())}[/dim]\n"
    )

    # --------------------------------------------------------
    # Setup prompt with history.
    # --------------------------------------------------------
    history_dir = Path.home() / ".quantum_mechanic"
    history_dir.mkdir(parents=True, exist_ok=True)
    history_file = history_dir / "shell_history"

    # --------------------------------------------------------
    # Direct command execution?
    # --------------------------------------------------------
    if args.command:
        # Join command + args and split by semicolon for chaining
        full_raw = " ".join([args.command] + args.args)
        for sub_cmd in full_raw.split(";"):
            parts = shlex.split(sub_cmd.strip())
            if not parts: continue
            _handle_command(state, parts[0].lower(), parts[1:])

        if state.workspace:
            state.workspace.close()
        return

    session: PromptSession = PromptSession(
        history=FileHistory(str(history_file)),
    )

    # --------------------------------------------------------
    # Main REPL loop.
    # --------------------------------------------------------
    while True:
        try:
            completer = _build_completer(state)
            prompt_text = state.prompt_context + "> "

            user_input = session.prompt(
                HTML(f"<b>{prompt_text}</b>"),
                completer=completer,
            ).strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                if state.workspace:
                    state.workspace.close()
                formatters.console.print("\n  [dim]Goodbye.[/dim]\n")
                break

            # --------------------------------------------------------
            # Parse the command and arguments (support semicolon chaining).
            # --------------------------------------------------------
            for cmd_segment in user_input.split(";"):
                try:
                    parts = shlex.split(cmd_segment.strip())
                except ValueError:
                    parts = cmd_segment.strip().split()

                if not parts: continue

                cmd_name = parts[0].lower()
                cmd_args = parts[1:]

                _handle_command(state, cmd_name, cmd_args)

        except KeyboardInterrupt:
            formatters.console.print()
            continue
        except EOFError:
            if state.workspace:
                state.workspace.close()
            formatters.console.print("\n  [dim]Goodbye.[/dim]\n")
            break
        except Exception as e:
            formatters.console.print(f"  [red]Error:[/red] {e}")
            logger.exception("Shell error")


def _handle_command(state: ShellState, cmd_name: str, cmd_args: list[str]) -> None:
    """Core command dispatch logic shared by REPL and direct execution."""
    from quantum_mechanic.shell.commands import COMMANDS

    handler = COMMANDS.get(cmd_name)
    if handler is None:
        # --------------------------------------------------------
        # If the input looks like a technique ID (contains /),
        # treat it as 'run <technique_id>' automatically.
        # The user shouldn't need to type 'run' every time.
        # --------------------------------------------------------
        if "/" in cmd_name and state.loader.get(cmd_name):
            from quantum_mechanic.shell.commands import cmd_run

            cmd_run(state, [cmd_name] + cmd_args)
            return

        formatters.console.print(
            f"  [red]✗[/red] Unknown command: {cmd_name}. Run 'help' for commands."
        )
        return

    handler(state, cmd_args)

