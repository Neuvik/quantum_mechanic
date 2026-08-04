# ================================================================
# MODULE: quantum_mechanic.agent.mode
# ----------------------------------------------------------------
# PURPOSE:   Non-interactive agent mode. All output is structured
#            JSON on stdout. Status on stderr. Never blocks for
#            input. Designed for AI agent consumption.
#
# USAGE:
#   qm --agent capabilities
#   qm --agent creds
#   qm --agent run discovery/whoami --credential 1
#   qm --agent import aws --profile sa_key1
# ================================================================

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueRunner
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.azure.auth import AzureAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.providers.entra.auth import EntraAuthProvider
from quantum_mechanic.providers.gcp.auth import GCPAuthProvider
from quantum_mechanic.providers.oci.auth import OCIAuthProvider

logger = logging.getLogger(__name__)


def _attach_file_logger(root_logger: logging.Logger, log_dir: Path) -> None:
    """Attach the rotating file logger when the target path is writable."""
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_dir / "qm.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
    except OSError as exc:
        logger.warning("File logging disabled: %s", exc)
        return

    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    root_logger.addHandler(file_handler)


def _json_out(data: dict[str, Any]) -> None:
    """Write compact JSON to stdout (for agent consumption).

    Uses compact separators — no indentation, no extra spaces.
    Token-efficient for LLM agent consumption.
    """
    print(json.dumps(data, separators=(",", ":"), default=str))


def _json_raw(data: dict[str, Any]) -> None:
    """Write indented JSON to stdout (for --raw mode or human inspection)."""
    print(json.dumps(data, indent=2, default=str))


def _error_out(message: str, exit_code: int = 1) -> None:
    """Write compact error JSON and exit with non-zero code."""
    _json_out({"ok": False, "error": message})
    sys.exit(exit_code)


def _build_registry() -> ProviderRegistry:
    """Build the provider registry."""
    registry = ProviderRegistry()
    registry.register(AWSAuthProvider())
    registry.register(AzureAuthProvider())
    registry.register(EntraAuthProvider())
    registry.register(GCPAuthProvider())
    registry.register(OCIAuthProvider())
    return registry


def run_agent_mode(args: argparse.Namespace, workspace_dir: Path | None = None) -> None:
    """Entry point for agent mode.

    Args:
        args:          Parsed CLI arguments.
        workspace_dir: Override the workspace storage directory.
                       Defaults to ~/.quantum_mechanic/workspaces.
                       Primarily used in tests to avoid touching the real dir.
    """
    # --------------------------------------------------------
    # Setup logging — minimal for console, verbose for background log
    # --------------------------------------------------------
    log_dir = Path.home() / ".quantum_mechanic" / "logs"

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    root_logger.addHandler(console_handler)
    _attach_file_logger(root_logger, log_dir)

    registry = _build_registry()
    loader = TechniqueLoader()
    loader.load_all()

    # --------------------------------------------------------
    # Parse the agent command from args.
    # --------------------------------------------------------
    command = args.command
    extra_args = args.args or []

    if command is None or command == "capabilities":
        _cmd_capabilities(registry, loader, args, workspace_dir=workspace_dir)
    elif command == "creds":
        _cmd_creds(args, workspace_dir=workspace_dir)
    elif command == "run":
        _cmd_run(extra_args, registry, loader, args, workspace_dir=workspace_dir)
    elif command == "import":
        _cmd_import(extra_args, args, workspace_dir=workspace_dir)
    elif command == "workspace":
        _cmd_workspace(extra_args, workspace_dir=workspace_dir)
    else:
        _error_out(f"Unknown agent command: {command}")


def _cmd_capabilities(
    registry: ProviderRegistry,
    loader: TechniqueLoader,
    args: argparse.Namespace,
    workspace_dir: Path | None = None,
) -> None:
    """Output the capabilities manifest."""
    providers = {}
    for name in registry.available():
        providers[name] = {"available": True}

    techniques = []
    for t in loader.list_all():
        techniques.append(
            {
                "id": t.metadata.id,
                "tactic": t.metadata.tactic,
                "providers": t.metadata.providers,
                "safe": t.metadata.safe,
                "description": t.metadata.description,
            }
        )

    # --------------------------------------------------------
    # Include workspace info if available.
    # --------------------------------------------------------
    workspace_info: dict[str, Any] | None = None
    credentials_info: list[dict[str, Any]] = []

    if args.workspace:
        try:
            ws = Workspace.load(args.workspace, workspace_dir=workspace_dir)
            workspace_info = {"name": ws.name}
            creds = ws.list_credentials()
            for c in creds:
                credentials_info.append(
                    {
                        "id": c.id,
                        "provider": c.provider,
                        "type": c.credential_type,
                        "identity": c.friendly_name,
                        "status": c.status,
                        "expires_at": c.expires_at,
                        "auto_refresh": c.auto_refresh,
                    }
                )
            ws.close()
        except Exception as e:
            workspace_info = {"error": str(e)}

    _json_out(
        {
            "ok": True,
            "capabilities": {
                "version": "0.1.0",
                "providers": providers,
                "techniques": techniques,
                "workspace": workspace_info,
                "credentials": credentials_info,
            },
        }
    )


def _cmd_creds(args: argparse.Namespace, workspace_dir: Path | None = None) -> None:
    """List credentials in agent mode."""
    if not args.workspace:
        _error_out("--workspace required for 'creds' command")

    try:
        ws = Workspace.load(args.workspace, workspace_dir=workspace_dir)
        creds = ws.list_credentials()
        _json_out(
            {
                "ok": True,
                "credentials": [
                    {
                        "id": c.id,
                        "provider": c.provider,
                        "type": c.credential_type,
                        "identity": c.friendly_name,
                        "status": c.status,
                        "expires_at": c.expires_at,
                    }
                    for c in creds
                ],
            }
        )
        ws.close()
    except Exception as e:
        _error_out(str(e))


def _cmd_run(
    extra_args: list[str],
    registry: ProviderRegistry,
    loader: TechniqueLoader,
    args: argparse.Namespace,
    workspace_dir: Path | None = None,
) -> None:
    """Run a technique in agent mode."""
    from quantum_mechanic.agent.summarizer import summarize

    if not args.workspace:
        _error_out("--workspace required for 'run' command")

    if not extra_args:
        _error_out("Usage: qm --agent run <technique_id> [--credential <id>] [--raw]")

    technique_id = extra_args[0]
    credential_id = None
    raw_output = "--raw" in extra_args

    for i, arg in enumerate(extra_args):
        if arg == "--credential" and i + 1 < len(extra_args):
            try:
                credential_id = int(extra_args[i + 1])
            except ValueError:
                _error_out(f"Invalid credential ID: {extra_args[i + 1]}")

    try:
        ws = Workspace.load(args.workspace, workspace_dir=workspace_dir)
        if credential_id is not None:
            ws.active_credential_id = credential_id

        runner = TechniqueRunner(ws, loader, registry)
        result = runner.run(technique_id, credential_id=credential_id)

        if raw_output:
            _json_raw(result.to_dict())
        else:
            registered = loader.get(technique_id)
            tactic = registered.metadata.tactic if registered else "unknown"
            summary = summarize(
                technique_id=technique_id,
                tactic=tactic,
                provider=result.provider,
                data=result.data,
                ok=(result.status == "success"),
                ms=result.duration_ms,
                api_calls=result.api_calls,
                error=result.error,
            )
            _json_out(summary.to_dict())

        ws.close()
    except Exception as e:
        _error_out(str(e))


def _cmd_import(extra_args: list[str], args: argparse.Namespace, workspace_dir: Path | None = None) -> None:
    """Import credentials in agent mode."""
    if not args.workspace:
        _error_out("--workspace required for 'import' command")

    if not extra_args:
        _error_out("Usage: qm --agent import <provider> [options]")

    provider = extra_args[0].lower()

    opts: dict[str, str] = {}
    i = 1
    while i < len(extra_args):
        if extra_args[i].startswith("--"):
            key = extra_args[i][2:]
            if i + 1 < len(extra_args) and not extra_args[i + 1].startswith("--"):
                opts[key] = extra_args[i + 1]
                i += 2
            else:
                opts[key] = "true"
                i += 1
        else:
            i += 1

    try:
        ws = Workspace.load(args.workspace, workspace_dir=workspace_dir)

        if provider == "aws":
            if "profile" in opts:
                secret = json.dumps({"profile_name": opts["profile"]})
                friendly = f"profile:{opts['profile']}"
            else:
                _error_out("AWS import requires --profile")
                return
            cred_id = ws.add_credential(
                provider="aws",
                credential_type="access_key",
                secret_data=secret,
                friendly_name=friendly,
                obtained_via="agent import",
            )
        elif provider == "azure":
            from quantum_mechanic.shell.commands import _capture_azure_token
            try:
                secret_dict = _capture_azure_token()
            except Exception as e:
                logger.error("Agent failed to capture Azure credential: %s", e)
                _error_out(f"Failed to capture Azure credential: {e}")
                return
            secret = json.dumps(secret_dict)
            friendly = secret_dict["captured_principal"]
            cred_id = ws.add_credential(
                provider="azure",
                credential_type="captured_token",
                secret_data=secret,
                friendly_name=friendly,
                obtained_via="agent import",
            )
        elif provider == "gcp":
            from quantum_mechanic.shell.commands import _capture_gcp_token
            try:
                secret_dict = _capture_gcp_token()
            except Exception as e:
                logger.error("Agent failed to capture GCP credential: %s", e)
                _error_out(f"Failed to capture GCP credential: {e}")
                return
            if not secret_dict.get("project_id") and opts.get("project"):
                secret_dict["project_id"] = opts["project"]
            secret = json.dumps(secret_dict)
            friendly = secret_dict["captured_principal"]
            cred_id = ws.add_credential(
                provider="gcp",
                credential_type="captured_token",
                secret_data=secret,
                friendly_name=friendly,
                obtained_via="agent import",
            )
        elif provider == "oci":
            profile = opts.get("profile", "DEFAULT")
            secret = json.dumps({"method": "config_file", "profile": profile})
            friendly = f"config:{profile}"
            cred_id = ws.add_credential(
                provider="oci",
                credential_type="api_key",
                secret_data=secret,
                friendly_name=friendly,
                obtained_via="agent import",
            )
        else:
            _error_out(f"Unsupported provider: {provider}")
            return

        _json_out(
            {
                "ok": True,
                "credential_id": cred_id,
                "provider": provider,
                "identity": friendly,
            }
        )
        ws.close()
    except Exception as e:
        _error_out(str(e))


def _cmd_workspace(extra_args: list[str], workspace_dir: Path | None = None) -> None:
    """Workspace operations in agent mode."""
    if not extra_args:
        _error_out("Usage: qm --agent workspace <create|list> [name]")

    subcmd = extra_args[0]

    if subcmd == "create":
        if len(extra_args) < 2:
            _error_out("Usage: qm --agent workspace create <name>")
        name = extra_args[1]
        try:
            ws = Workspace.create(name, workspace_dir=workspace_dir)
            _json_out({"ok": True, "workspace": name})
            ws.close()
        except FileExistsError:
            _error_out(f"Workspace '{name}' already exists")

    elif subcmd == "list":
        workspaces = Workspace.list_all(workspace_dir=workspace_dir)
        _json_out({"ok": True, "workspaces": workspaces})

    else:
        _error_out(f"Unknown workspace command: {subcmd}")
