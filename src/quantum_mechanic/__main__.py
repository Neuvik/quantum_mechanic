# ================================================================
# MODULE: quantum_mechanic.__main__
# ----------------------------------------------------------------
# PURPOSE:   Entry point for Quantum Mechanic.
#
#            Two modes of operation:
#              qm              → interactive shell (human operator)
#              qm --agent      → structured JSON mode (AI agent)
#              qm --agent capabilities → what's available
#
# USAGE:     python -m quantum_mechanic [--agent] [command] [args]
# ================================================================

from __future__ import annotations

import argparse
import contextlib

from quantum_mechanic import __version__


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Uses parse_known_args so agent subcommand flags (--profile,
    --credential, etc.) don't conflict with top-level flags.
    """
    parser = argparse.ArgumentParser(
        prog="qm",
        description="Quantum Mechanic — Cross-cloud offensive security framework",
    )
    parser.add_argument(
        "--agent",
        action="store_true",
        help="Run in agent mode (structured JSON output, no interactive prompts)",
    )
    parser.add_argument(
        "--workspace",
        "-w",
        type=str,
        default=None,
        help="Workspace name to load on startup",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # --------------------------------------------------------
    # Parse only the known top-level args. Everything else
    # (command name + subcommand flags) goes to remaining.
    # --------------------------------------------------------
    known, remaining = parser.parse_known_args()

    # Split remaining into command + args
    known.command = remaining[0] if remaining else None
    known.args = remaining[1:] if len(remaining) > 1 else []

    return known


def main() -> int | None:
    """Main entry point for Quantum Mechanic.

    Returns an int exit code for the `graph` subcommand (consumed by the
    console-script wrapper); returns None (exit 0) for the interactive/agent
    modes.
    """
    # Activate the in-binary call-edge tracer when QM_TRACE=1 (the dynamic
    # `qm graph trace` run sets it for pexpect-spawned subprocesses). Guarded
    # so a codegraph import/setup hiccup can never break normal `qm` startup;
    # tracing is best-effort, so any failure here is silently ignored.
    with contextlib.suppress(Exception):
        from quantum_mechanic.codegraph.tracer import install_from_env

        install_from_env()

    args = parse_args()

    if args.command == "graph":
        from quantum_mechanic.codegraph import cli

        return cli.run(args.args)

    if args.agent:
        from quantum_mechanic.agent.mode import run_agent_mode

        run_agent_mode(args)
    else:
        from quantum_mechanic.shell.app import run_shell

        run_shell(args)

    return None


if __name__ == "__main__":
    raise SystemExit(main())
