# ================================================================
# MODULE: quantum_mechanic.shell.commands
# ----------------------------------------------------------------
# PURPOSE:   Shell command handlers.
#            Each command is a function that takes the shell state
#            and arguments, executes the operation, and displays
#            results through formatters.
#
# DESIGN:    Commands are registered in a dict for dispatch.
#            Each command returns None (output is via formatters).
#            Commands handle their own argument parsing.
# ================================================================

from __future__ import annotations

import base64
import json
import logging
import os
import queue
from contextlib import nullcontext
from datetime import UTC
from pathlib import Path
from typing import Any

from rich.console import Console

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.playbook import PlaybookRunner
from quantum_mechanic.core.runner import TechniqueRunner
from quantum_mechanic.core.transport import LocalTransport, Transport
from quantum_mechanic.core.workspace import CredentialMismatchError, Workspace
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell import formatters
from quantum_mechanic.shell.command_help import CommandHelp, FlagHelp, SubcommandHelp
from quantum_mechanic.shell.commands_entra import acquire_entra, export_entra, import_entra

logger = logging.getLogger(__name__)
console = Console()


class ShellState:
    """Mutable state for the interactive shell session."""

    def __init__(
        self,
        workspace: Workspace | None = None,
        loader: TechniqueLoader | None = None,
        registry: ProviderRegistry | None = None,
        transport: Transport | None = None,
        workspace_dir: Path | None = None,
    ) -> None:
        self.workspace = workspace
        self.loader = loader or TechniqueLoader()
        self.registry = registry or ProviderRegistry()
        self._transport = transport  # explicit transport (e.g. RemoteTransport)

        # If no explicit transport provided but workspace exists, build local one.
        if self._transport is None and self.workspace is not None:
            self._transport = LocalTransport(self.workspace, self.loader, self.registry)

        self.active_credential_id: int | None = None
        self.active_credential_label: str | None = None
        # Providers unlocked beyond the base credential provider (e.g. "azure"
        # added after ARM FOCI expansion while the base credential is "entra").
        self._extra_providers: list[str] = []
        # Optional override for where workspaces are stored.
        # Set in tests to a tmp_path; None means the default user directory.
        self.workspace_dir: Path | None = workspace_dir
        self._agent_update_callback = None

    @property
    def transport(self) -> Transport | None:
        """The active transport (Local or Remote)."""
        return self._transport

    def set_workspace(self, workspace: Workspace | None) -> None:
        """Update the active workspace and re-initialise the local transport.

        Passing None clears the active workspace (e.g. after deleting it) and
        drops the transport — subsequent commands that need a workspace will
        prompt the operator to create one.
        """
        self.workspace = workspace
        if workspace is None:
            self._transport = None
        else:
            self._transport = LocalTransport(workspace, self.loader, self.registry)
        self.active_credential_id = None
        self.active_credential_label = None
        self._extra_providers = []

        # Re-register callback if one was active
        if self._agent_update_callback and self.workspace is not None:
            self.workspace.on_agent_update(self._agent_update_callback)

    def on_agent_update(self, callback) -> None:
        """Register a callback for agent lifecycle events."""
        self._agent_update_callback = callback
        if self.workspace:
            self.workspace.on_agent_update(callback)

    @property
    def runner(self) -> TechniqueRunner | None:
        """Deprecated: use self.transport instead.

        Kept for compatibility with code that hasn't been migrated yet.
        Will be removed once all callers use Transport.
        """
        if self.workspace is None:
            return None
        return TechniqueRunner(self.workspace, self.loader, self.registry)

    @property
    def playbook_runner(self) -> PlaybookRunner | None:
        """The active playbook runner."""
        r = self.runner
        return PlaybookRunner(r) if r else None

    @property
    def prompt_context(self) -> str:
        """Build the prompt context string.

        Remote mode:  qm[remote:alice@qmd.example.com:8443][cred:1]
        Local mode:   qm[workspace][cred:1]
        """
        parts = ["qm"]

        if self._transport is not None:
            op = getattr(self._transport, "operator", None)
            host = getattr(self._transport, "host", None)
            if op and host:
                parts.append(f"[remote:{op}@{host}]")
            elif self.workspace:
                # Local mode with a transport active
                parts.append(f"[{self.workspace.name}]")
        elif self.workspace:
            parts.append(f"[{self.workspace.name}]")

        if self.active_credential_label is not None:
            parts.append(f"[{self.active_credential_label}]")
        elif self.active_credential_id is not None:
            parts.append(f"[cred:{self.active_credential_id}]")
        elif self.workspace and self.workspace.active_credential_id:
            # Fallback for when state wasn't updated via `use` but workspace has one
            cred = self.workspace.get_credential(self.workspace.active_credential_id)
            if cred:
                identity = cred.friendly_name or cred.provider
                parts.append(f"[{cred.provider}:{identity}]")

        return "".join(parts)


def cmd_workspace(state: ShellState, args: list[str]) -> None:
    """Workspace management: create, load, list."""
    if not args:
        if state.workspace:
            console.print(f"  Active workspace: [bold]{state.workspace.name}[/bold]")
        else:
            console.print("  No active workspace. Run 'workspace create <name>'", style="dim")
        return

    # Subcommand validation — print suggestion if unknown
    err = _check_subcommand("workspace", args)
    if err:
        console.print(err)
        return

    subcmd = args[0]

    if subcmd == "create":
        if len(args) < 2:
            console.print("  Usage: workspace create <name>", style="yellow")
            return
        name = args[1]
        try:
            ws = Workspace.create(name, workspace_dir=state.workspace_dir)
            state.set_workspace(ws)
            console.print(f"  [green]✓[/green] Created workspace: [bold]{name}[/bold]")
        except FileExistsError:
            console.print(f"  [red]✗[/red] Workspace '{name}' already exists", style="red")

    elif subcmd == "load":
        if len(args) < 2:
            console.print("  Usage: workspace load <name>", style="yellow")
            return
        name = args[1]
        try:
            ws = Workspace.load(name, workspace_dir=state.workspace_dir)
            state.set_workspace(ws)
            console.print(f"  [green]✓[/green] Loaded workspace: [bold]{name}[/bold]")
        except FileNotFoundError:
            console.print(f"  [red]✗[/red] Workspace '{name}' not found", style="red")

    elif subcmd == "list":
        workspaces = Workspace.list_all(workspace_dir=state.workspace_dir)
        if not workspaces:
            console.print("  No workspaces found.", style="dim")
        else:
            for ws in workspaces:
                console.print(f"  • {ws['name']}  [dim]({ws['modified']})[/dim]")

    elif subcmd == "delete":
        if len(args) < 2:
            console.print("  Usage: workspace delete <name>", style="yellow")
            return
        name = args[1]
        # Guard: if the workspace being deleted is the currently active one,
        # close and clear session state first so the .db file isn't held open.
        if state.workspace is not None and state.workspace.name == name:
            state.workspace.close()
            state.set_workspace(None)
        try:
            Workspace.delete(name, workspace_dir=state.workspace_dir)
            console.print(f"  [green]✓[/green] Deleted workspace: [bold]{name}[/bold]")
        except FileNotFoundError:
            console.print(f"  [red]✗[/red] Workspace '{name}' not found", style="red")
        except Exception as e:
            console.print(f"  [red]✗[/red] Could not delete workspace '{name}': {e}", style="red")

    else:
        console.print(
            f"  Unknown subcommand: {subcmd}. Use: create, load, list, delete",
            style="yellow",
        )


def cmd_import(state: ShellState, args: list[str]) -> None:
    """Import credentials: import <provider> [options]."""
    if state.transport is None:
        console.print(
            "  [red]✗[/red] No active workspace/connection. Run 'workspace create <name>' first."
        )
        return

    # Subcommand validation — print suggestion if unknown
    err = _check_subcommand("import", args)
    if err:
        console.print(err)
        return

    if not args:
        console.print("  Usage: import <provider> [options]", style="yellow")
        console.print("    import aws --profile <name>")
        console.print("    import aws --access-key <key> --secret-key <secret>")
        console.print("    import azure --default")
        console.print(
            "    import azure --client-id <id> --client-secret <secret> --tenant-id <tid>"
        )
        console.print("    import azure --access-token <jwt> [--expires-on <unix-epoch>]")
        console.print("    import gcp --default")
        console.print("    import gcp --key-file /path/to/sa.json")
        console.print("    import oci --default")
        console.print("    import oci --profile <profile_name>")
        console.print(
            "    import oci --user <id> --tenancy <id> --fingerprint <hash> --key-file <path> --region <reg>"
        )
        console.print("    import entra browserdump /path/to/dump.json")
        console.print(
            "    import entra browser_cdp [--browser edge|chrome] [--launch]   (phase 1: launch)"
        )
        console.print(
            "    import entra browser_cdp --attach [--port <n>]                (phase 2: import)"
        )
        console.print("    import entra roadtools /path/to/.roadtools_auth")
        console.print("    import entra access_token <jwt> [--tenant <tid>]")
        console.print("    import entra refresh_token <token> --tenant <tid> --client <id>")
        console.print("    import entra prt_cookie <jwt>")
        console.print("    import entra ests_cookie <value> --tenant <tid>")
        console.print("    import entra prt_key <prt> --session-key <key> --tenant <tid>")
        return

    provider = args[0].lower()
    opts = _parse_opts(args[1:])

    if provider == "aws":
        _import_aws(state, opts)
    elif provider == "azure":
        _import_azure(state, opts)
    elif provider == "gcp":
        _import_gcp(state, opts)
    elif provider == "oci":
        _import_oci(state, opts)
    elif provider == "entra":
        import_entra(state, args[1:])
    else:
        console.print(
            f"  [red]✗[/red] Unsupported provider: {provider}. Use: aws, azure, gcp, oci, entra"
        )


def _validate_and_import(
    state: ShellState,
    provider: str,
    credential_type: str,
    secret: dict,
    friendly: str,
) -> None:
    """Validate credentials by authenticating, then store if valid.

    Tries to call provider.authenticate() before storing anything.
    If authentication fails, show the error and don't store.
    """
    from quantum_mechanic.core.runner import _friendly_error

    # --------------------------------------------------------
    # Try to authenticate before storing anything.
    # --------------------------------------------------------
    provider_impl = state.registry.get(provider)
    if provider_impl is None:
        console.print(f"  [red]✗[/red] Provider '{provider}' not available.")
        return

    try:
        session = provider_impl.authenticate(secret)
    except Exception as e:
        friendly_msg = _friendly_error(e, provider)
        console.print(f"  [red]✗[/red] {friendly_msg}")
        return

    # --------------------------------------------------------
    # Capture the stable identity claim (principal_id, e.g. the ARN
    # for AWS) via whoami so the isolation guard has something to
    # verify against later. Failure here shouldn't block import —
    # the credential authenticated fine and whoami quirks are their
    # own class of problem; skip identity capture and note it.
    # --------------------------------------------------------
    principal_id: str | None = None
    try:
        who = provider_impl.whoami(session)
        candidate = getattr(who, "principal_id", None)
        # Only accept a real string — a MagicMock or other object here means
        # whoami was mocked-away in tests, or the provider's whoami didn't
        # populate the field. In either case we treat identity as unknown
        # and fall through to the backward-compat verification path.
        if isinstance(candidate, str) and candidate:
            principal_id = candidate
    except Exception as e:
        # Non-fatal — cred still stores, just without a stable identity.
        # verify_credential_identity will recover it on first use.
        logger.debug("whoami at import failed for %s: %s", provider, e)

    # --------------------------------------------------------
    # Credentials are valid — store them.
    # --------------------------------------------------------
    cred_id = state.transport.add_credential(  # type: ignore[union-attr]
        provider=provider,
        credential_type=credential_type,
        secret_data=json.dumps(secret),
        friendly_name=friendly,
        principal_id=principal_id,
    )
    console.print(
        f"  [green]✓[/green] Imported {provider.upper()} credential #{cred_id}: {friendly}"
    )


def _check_subcommand(command_name: str, args: list[str]) -> str | None:
    """If args[0] looks like a subcommand but isn't valid, return a friendly error message.

    Returns None if args is empty, args[0] is a flag, or args[0] is a recognized
    subcommand. Returns a multi-line suggestion string when args[0] is an
    unknown subcommand.
    """
    if not args:
        return None
    first = args[0]
    if first.startswith("--"):
        return None  # flags are handled elsewhere

    help_rec = COMMAND_HELP.get(command_name)
    if not help_rec or not help_rec.subcommands:
        return None  # no subcommands declared; positional args mean something else

    known = [s.name for s in help_rec.subcommands]
    # Match against the full subcommand name OR its first word — for commands
    # like `acquire entra device_code`, args[0]="entra" should match the
    # subcommand "entra device_code".
    known_first_words = {name.split()[0] for name in known if name}
    if first in known or first in known_first_words:
        return None

    import difflib

    matches = difflib.get_close_matches(first, known, n=2, cutoff=0.4)
    suggestion = matches[0] if matches else known[0]
    available = ", ".join(known)
    return (
        f"  [red]✗[/red] Unknown subcommand: '{first}'. "
        f"Did you mean: [bold]{command_name} {suggestion}[/bold]?\n"
        f"  Available subcommands: {available}\n"
        f"  Try `help {command_name}` for full usage."
    )


def _import_aws(state: ShellState, opts: dict[str, str]) -> None:
    """Import AWS credentials."""
    if "profile" in opts:
        secret: dict = {"profile_name": opts["profile"]}
        if "region" in opts:
            secret["region"] = opts["region"]
        friendly = f"profile:{opts['profile']}"
        cred_type = "access_key"
    elif "access-key" in opts and "secret-key" in opts:
        secret = {
            "access_key_id": opts["access-key"],
            "secret_access_key": opts["secret-key"],
        }
        if "session-token" in opts:
            secret["session_token"] = opts["session-token"]
            cred_type = "session_token"
        else:
            cred_type = "access_key"
        if "region" in opts:
            secret["region"] = opts["region"]
        friendly = f"key:{opts['access-key'][:8]}..."
    else:
        console.print("  [red]✗[/red] AWS import requires --profile or --access-key + --secret-key")
        return

    _validate_and_import(state, "aws", cred_type, secret, friendly)


def _import_azure(state: ShellState, opts: dict[str, str]) -> None:
    """Import Azure credentials.

    For --default: captures a Management access token from local state ONCE,
    persists it. The credential is then isolated from later az login changes.

    For --client-id/--client-secret: persists service-principal creds.
    For --access-token: persists a captured ARM token directly.
    """
    if "access-token" in opts:
        token = opts.get("access-token", "").strip()
        if not token:
            console.print("  [red]✗[/red] --access-token requires a JWT value")
            return

        claims: dict[str, Any] = {}
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload = parts[1]
                payload += "=" * (-len(payload) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
        except Exception:
            claims = {}

        expires_on = opts.get("expires-on")
        if expires_on is None:
            exp = claims.get("exp")
            if exp is None:
                console.print(
                    "  [red]✗[/red] Could not derive token expiration from JWT. "
                    "Pass --expires-on <unix-epoch>."
                )
                return
            expires_on = str(exp)

        try:
            expires_on_int = int(expires_on)
        except ValueError:
            console.print("  [red]✗[/red] --expires-on must be a unix epoch integer")
            return

        principal = (
            claims.get("appid") or claims.get("upn") or claims.get("oid") or "azure-access-token"
        )
        secret: dict[str, Any] = {
            "method": "captured_token",
            "access_token": token,
            "expires_on": expires_on_int,
            "captured_principal": principal,
        }
        friendly = opts.get("friendly", f"TOKEN:{str(principal)[:24]}")
        cred_type = "captured_token"
        _validate_and_import(state, "azure", cred_type, secret, friendly)
        return

    if "client-id" in opts:
        if not all(k in opts for k in ["client-id", "client-secret", "tenant-id"]):
            console.print(
                "  [red]✗[/red] SP auth requires --client-id, --client-secret, and --tenant-id"
            )
            return
        secret: dict = {
            "tenant_id": opts["tenant-id"],
            "client_id": opts["client-id"],
            "client_secret": opts["client-secret"],
        }
        friendly = opts.get("friendly", f"SP:{opts['client-id'][:8]}")
        cred_type = "service_principal"
        _validate_and_import(state, "azure", cred_type, secret, friendly)
        return

    # --default path: capture token once at import time.
    try:
        console.print("  [dim]Capturing Azure credential from local state...[/dim]")
        secret = _capture_azure_token()
        friendly = secret["captured_principal"]
        cred_type = "captured_token"
    except Exception as e:
        console.print(f"  [red]✗[/red] Failed to capture Azure credential: {e}")
        console.print("  [dim]Ensure you are logged in: `az login`[/dim]")
        return

    _validate_and_import(state, "azure", cred_type, secret, friendly)


def _import_gcp(state: ShellState, opts: dict[str, str]) -> None:
    """Import GCP credentials."""
    if "key-file" in opts:
        secret: dict = {
            "method": "service_account_file",
            "key_file": opts["key-file"],
        }
        friendly = f"SA:{opts['key-file'].split('/')[-1]}"
        cred_type = "service_account"
    else:
        # --default path: capture token from ADC once.
        try:
            console.print("  [dim]Capturing GCP credential from local ADC state...[/dim]")
            secret = _capture_gcp_token()
            if not secret.get("project_id") and opts.get("project"):
                secret["project_id"] = opts["project"]
            friendly = secret["captured_principal"]
            cred_type = "captured_token"
        except Exception as e:
            console.print(f"  [red]✗[/red] Failed to capture GCP credential: {e}")
            console.print("  [dim]Ensure: `gcloud auth application-default login`[/dim]")
            return

    if "project" in opts and "project_id" not in secret:
        secret["project_id"] = opts["project"]

    _validate_and_import(state, "gcp", cred_type, secret, friendly)


def _import_oci(state: ShellState, opts: dict[str, str]) -> None:
    """Import OCI credentials."""
    if all(k in opts for k in ["user", "tenancy", "fingerprint", "key-file", "region"]):
        try:
            with open(opts["key-file"]) as f:
                key_content = f.read()
        except OSError as e:
            console.print(f"  [red]✗[/red] Could not read OCI key file: {e}")
            return

        secret: dict[str, str] = {
            "method": "inline",
            "user": opts["user"],
            "tenancy": opts["tenancy"],
            "fingerprint": opts["fingerprint"],
            "key_content": key_content,
            "region": opts["region"],
        }
        friendly = f"OCI User:{opts['user'][:8]}..."
    else:
        profile = opts.get("profile", "DEFAULT")
        config_file = opts.get("config-file")

        secret = {"method": "config_file", "profile": profile}
        if config_file:
            secret["config_file"] = config_file
        friendly = f"config:{profile}"

    _validate_and_import(state, "oci", "api_key", secret, friendly)


def _cmd_creds_detail(state: ShellState, cred_id: int) -> None:
    """Show per-token detail for one credential (expirations, scopes, roles).

    Entra token_store creds get full per-token breakdown; other providers
    render as a simple key/value block since they have no multi-token
    substructure to unfold.
    """
    if state.workspace is None:
        console.print("  [red]✗[/red] No active workspace.")
        return
    creds = state.transport.list_credentials() if state.transport else []
    cred = next((c for c in creds if c.get("id") == cred_id), None)
    if cred is None:
        console.print(f"  [red]✗[/red] Credential #{cred_id} not found")
        return

    provider = cred.get("provider")
    ctype = cred.get("credential_type")

    if provider == "entra" and ctype == "token_store":
        import json as _json

        from quantum_mechanic.providers.entra.token_store import EntraTokenStore as _ETS

        try:
            raw = state.workspace.get_credential_secret(cred_id)
            data = _json.loads(raw) if raw else {}
            store = _ETS.from_dict(data.get("token_store", data))
            details = store.token_details()
        except Exception as e:
            console.print(f"  [red]✗[/red] Failed to load token store: {e}")
            return
        formatters.format_credential_detail(cred, details)
        return

    # Non-entra fallback: dump the row fields the operator can act on.
    formatters.format_credential_detail(cred, [])


def cmd_creds(state: ShellState, args: list[str]) -> None:
    """List or delete credentials: creds, creds <id>, creds delete <id>."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    # `creds <id>` — bare int arg → detail view for one credential.
    if args and args[0].isdigit():
        cred_id = int(args[0])
        _cmd_creds_detail(state, cred_id)
        return

    # Subcommand validation — print suggestion if unknown
    err = _check_subcommand("creds", args)
    if err:
        console.print(err)
        return

    # Handle subcommands
    if args and args[0] == "delete":
        if len(args) < 2:
            console.print("  Usage: creds delete <id>", style="yellow")
            return
        try:
            cred_id = int(args[1])
        except ValueError:
            console.print(f"  [red]✗[/red] Invalid credential ID: {args[1]}")
            return
        if state.transport.delete_credential(cred_id):
            console.print(f"  [green]✓[/green] Deleted credential #{cred_id}")
            if state.active_credential_id == cred_id:
                state.active_credential_id = None
        else:
            console.print(f"  [red]✗[/red] Credential #{cred_id} not found")
        return

    provider = None
    status = None
    for i, arg in enumerate(args):
        if arg == "--provider" and i + 1 < len(args):
            provider = args[i + 1]
        elif arg == "--active":
            status = "active"

    # NOTE: Transport natively doesn't filter by status, but we can filter it locally
    creds = state.transport.list_credentials(provider=provider)
    if status:
        creds = [c for c in creds if c.get("status") == status]

    # Enrich Entra token_store entries with token summary and recovered identity.
    if state.workspace:
        import json as _json

        from quantum_mechanic.providers.entra.token_store import EntraTokenStore as _ETS
        from quantum_mechanic.shell.commands_entra import _entra_friendly_name

        for cred in creds:
            if cred.get("provider") == "entra" and cred.get("credential_type") == "token_store":
                try:
                    raw = state.workspace.get_credential_secret(cred["id"])
                    if not raw:
                        continue
                    data = _json.loads(raw)
                    store = _ETS.from_dict(data.get("token_store", data))
                    # Compact summary + soonest-expiring AT so the operator
                    # knows at a glance how much time is left on the active
                    # working token. Full breakdown via `creds <id>`.
                    summary = store.token_summary()
                    ats = [
                        d
                        for d in store.token_details()
                        if d.get("token_type") == "access_token"
                        and not d.get("is_expired")
                        and d.get("minutes_remaining") is not None
                    ]
                    if ats:
                        soonest = min(ats, key=lambda d: d["minutes_remaining"])
                        mins = int(soonest["minutes_remaining"])
                        summary = f"{summary}  ({soonest['kind'].split()[0]} {mins}m)"
                    cred["_token_summary"] = summary
                    # Recover identity from token claims if stored name is generic.
                    current_name = cred.get("friendly_name", "")
                    import re as _re

                    stale = (
                        not current_name
                        or current_name == "entra:common"
                        or current_name.startswith("entra:unknown")
                        # Old format had tenant suffix: "upn@domain (tenant)" or "upn (common)"
                        or bool(_re.search(r"@.+\s+\(", current_name))
                    )
                    if stale:
                        recovered = _entra_friendly_name(store)
                        if recovered != current_name:
                            cred["friendly_name"] = recovered
                            # Persist the recovered name so it shows correctly next time.
                            state.workspace.update_credential_secret(
                                cred["id"],
                                _json.dumps({"token_store": store.to_dict()}),
                                friendly_name=recovered,
                            )
                except Exception:
                    pass

    formatters.format_credentials(creds)


def _try_restore_arm_pivot(state: ShellState) -> None:
    """If the active Entra credential has ARM/FOCI capability, unlock Azure techniques."""
    import logging as _logging

    _log = _logging.getLogger("qm.shell")

    if state.workspace is None or state.active_credential_id is None:
        return

    # Fast path: inspect raw secret JSON without going through the full auth stack.
    # This avoids any dependency on EntraAuthProvider.authenticate() and is more
    # resilient to import / ORM issues.
    try:
        import json as _json
        from datetime import datetime as _dt

        raw = state.workspace.get_credential_secret(state.active_credential_id)
        if not raw:
            return
        secret = _json.loads(raw)
        tokens = secret.get("token_store", secret).get("tokens", [])

        arm = "https://management.azure.com"
        for tok in tokens:
            ttype = tok.get("token_type", "")
            resource = tok.get("resource", "").rstrip("/")
            exp_str = tok.get("expires_at")

            if ttype == "access_token" and resource == arm:
                # Check expiry
                if exp_str:
                    exp_dt = _dt.fromisoformat(exp_str)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=UTC)
                    if _dt.now(UTC) >= exp_dt:
                        continue  # expired, skip
                state._extra_providers = ["azure"]
                console.print("  [dim]↳ ARM token found — Azure techniques unlocked.[/dim]")
                return

            if ttype == "refresh_token" and tok.get("foci") and resource == arm:
                # ARM-scoped FOCI RT: user previously ran `acquire entra arm` and
                # the RT was stored. It can derive a new ARM AT on demand.
                state._extra_providers = ["azure"]
                console.print("  [dim]↳ FOCI token found — Azure techniques unlocked.[/dim]")
                return

    except Exception as exc:
        _log.debug("_try_restore_arm_pivot failed: %s", exc)


def cmd_use(state: ShellState, args: list[str]) -> None:
    """Set the active credential: use <id> | use none."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace/connection.")
        return

    if not args:
        console.print("  Usage: use <credential_id>  |  use none", style="yellow")
        return

    if args[0].lower() in ("none", "0", "clear"):
        state.active_credential_id = None
        state.active_credential_label = None
        state._extra_providers = []
        if state.workspace:
            state.workspace.active_credential_id = None
        console.print("  [dim]Active credential cleared.[/dim]")
        return

    try:
        cred_id = int(args[0])
    except ValueError:
        console.print(f"  [red]✗[/red] Invalid credential ID: {args[0]}")
        return

    creds = state.transport.list_credentials()
    cred = next((c for c in creds if c.get("id") == cred_id), None)
    if not cred:
        console.print(f"  [red]✗[/red] Credential #{cred_id} not found")
        return

    # Attempt workspace activation FIRST — if this raises, shell state stays
    # untouched so the prompt indicator doesn't lie about an active credential.
    if state.workspace:
        try:
            state.workspace.active_credential_id = cred_id
        except CredentialMismatchError as e:
            console.print(f"  [red]✗[/red] {e}")
            return  # do NOT mirror to shell state

    # Workspace setter succeeded (or no workspace) — safe to mirror.
    state.active_credential_id = cred_id
    state._extra_providers = []

    provider = cred.get("provider", "unknown")
    identity = cred.get("friendly_name") or cred.get("credential_type", "unknown")
    # Use friendly_name directly — it already encodes the provider context.
    state.active_credential_label = identity

    console.print(f"  [green]✓[/green] Active: {provider.upper()} {identity} (#{cred_id})")

    if provider == "entra":
        _try_restore_arm_pivot(state)


# ── Loot-backed interactive pickers ──────────────────────────────────────────
# Maps (technique_id, param_name) → (loot_technique, value_col, display_cols)
# When a required param is missing and loot exists, we offer a numbered picker.
_LOOT_PICKERS: dict[tuple[str, str], dict] = {
    ("lateral_movement/vm_execute_command", "target"): {
        "loot_technique": "discovery/enum_compute",
        "value_col": "vm_id",
        "display_cols": ["instance_id", "state", "os_type", "private_ip", "public_ip", "region"],
        "state_col": "state",
    },
    ("lateral_movement/vm_ssh_push", "target"): {
        "loot_technique": "discovery/enum_compute",
        "value_col": "instance_id",  # GCP uses VM name; OCI requires manual OCID
        "display_cols": ["instance_id", "state", "os_type", "private_ip", "public_ip", "region"],
        "state_col": "state",
    },
}


# Maps (technique_id, param_name) → directory of built-in options to show as a picker.
_FILE_PICKERS: dict[tuple[str, str], dict] = {
    ("discovery/enum_s3_buckets", "wordlist"): {
        "directory": "data/wordlists",
        "extension": ".txt",
        "label": "Built-in wordlists (or type a file path):",
    },
}


def _file_pick(directory: str, extension: str, label: str) -> str | None:
    """List files in a package data directory and let the user pick one by number."""
    from pathlib import Path

    from rich import box
    from rich.table import Table

    data_dir = Path(__file__).parent.parent / directory
    files = sorted(data_dir.glob(f"*{extension}")) if data_dir.exists() else []

    if not files:
        return None

    console.print(f"  [dim]{label}[/dim]")
    tbl = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    tbl.add_column("#", style="bold cyan", width=4)
    tbl.add_column("Name", style="bold")
    tbl.add_column("Entries", style="dim")
    for i, f in enumerate(files, 1):
        try:
            count = sum(
                1
                for line in f.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            )
        except Exception:
            count = 0
        tbl.add_row(str(i), f.stem, f"{count} names")
    console.print(tbl)
    console.print("  [dim]Pick a number or type a file path — Enter to cancel:[/dim]")

    try:
        choice = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if not choice:
        return None

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            return files[idx].stem
    except ValueError:
        # Treat as a literal path
        return choice if choice else None

    return None


_STATE_COLORS = {
    "running": "green",
    "started": "green",
    "deallocated": "red",
    "stopped": "yellow",
    "stopping": "yellow",
    "deallocating": "red",
}


def _loot_pick(
    state: ShellState,
    loot_technique: str,
    value_col: str,
    display_cols: list[str],
    state_col: str | None = None,
) -> str | None:
    """Load loot for *loot_technique*, present a numbered picker, return the chosen value_col value."""
    import csv
    from pathlib import Path

    from rich import box
    from rich.table import Table

    if state.workspace is None:
        return None

    ws_db = Path(state.workspace.db_path)
    csv_path = ws_db.parent / ws_db.stem / "loot" / loot_technique / "loot.csv"
    if not csv_path.exists():
        console.print(
            f"  [dim]No loot for {loot_technique} — run it first to populate targets.[/dim]"
        )
        return None

    try:
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
    except Exception:
        return None

    # Deduplicate by first column (instance_id), keeping last write
    if rows:
        pk = list(rows[0].keys())[0]
        keyed: dict = {}
        for row in rows:
            keyed[row.get(pk, "")] = row
        rows = [r for r in keyed.values() if r.get(value_col)]

    if not rows:
        console.print(f"  [dim]No {value_col} entries in loot — run {loot_technique} first.[/dim]")
        return None

    cols = [c for c in display_cols if c in (rows[0] if rows else {})]

    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("#", style="bold cyan", width=4)
    for col in cols:
        table.add_column(col.replace("_", " ").title())

    for i, row in enumerate(rows, 1):
        cells = []
        for c in cols:
            val = row.get(c, "")
            if c == state_col and val:
                color = _STATE_COLORS.get(val.lower(), "dim")
                cells.append(f"[{color}]{val}[/{color}]")
            else:
                cells.append(val)
        table.add_row(str(i), *cells)

    console.print(table)
    console.print(f"  [dim]Select a target (1-{len(rows)}) or press Enter to cancel:[/dim]")

    try:
        choice = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if not choice:
        return None

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(rows):
            selected = rows[idx]
            if state_col:
                pwr = selected.get(state_col, "").lower()
                if pwr and pwr not in ("running", "started", "unknown", "n/a", ""):
                    console.print(
                        f"  [yellow]⚠ VM state is '{pwr}' — command will likely fail.[/yellow]"
                    )
            return selected.get(value_col)
    except ValueError:
        pass

    console.print("  [yellow]Invalid selection.[/yellow]")
    return None


def _prompt_param(name: str, example: str | None = None) -> str | None:
    """Prompt the user for a single param value inline."""
    hint = f" (e.g. {example})" if example else ""
    console.print(f"  [dim]Enter {name}{hint}:[/dim]")
    try:
        value = input("  > ").strip()
        return value or None
    except (EOFError, KeyboardInterrupt):
        return None


def _maybe_offer_scope_retry(state: ShellState, result, technique_id: str, params: dict):
    """If `result` is a scope-denied Entra technique with a FOCI RT available,
    prompt the operator to attempt FOCI scope expansion and re-run once.

    Returns the fresh TechniqueResult on retry (success or a new failure), or
    None to keep the original denied result. Never raises — prompt errors,
    non-entra creds, and missing RTs all fall through as no-ops.
    """
    from quantum_mechanic.core.runner import TechniqueResult

    if not isinstance(result, TechniqueResult):
        return None
    if result.status != "denied":
        return None
    if not isinstance(result.data, dict):
        return None
    required_scope = result.data.get("required_scope")
    if not required_scope:
        return None
    if state.active_credential_id is None or state.transport is None:
        return None

    # Active cred must be entra.
    _creds = state.transport.list_credentials() if state.transport else []
    _cred = next((c for c in _creds if c.get("id") == state.active_credential_id), None)
    if _cred is None or _cred.get("provider") != "entra":
        return None

    # Load the store and verify it has a FOCI RT — no RT means nothing to expand.
    try:
        from quantum_mechanic.providers.entra.scope_exchange import try_acquire_scope
        from quantum_mechanic.providers.entra.token_store import EntraTokenStore

        raw = (
            state.workspace.get_credential_secret(state.active_credential_id)
            if state.workspace
            else None
        )
        if not raw:
            return None
        data = json.loads(raw)
        store = EntraTokenStore.from_dict(data.get("token_store", data))
    except Exception:
        return None
    if store.foci_refresh_token() is None:
        return None

    # Prompt the operator. Rich's Confirm.ask blocks on stdin — safe now that
    # the Live spinner is torn down.
    from rich.prompt import Confirm

    try:
        answered_yes = Confirm.ask(
            f"  [yellow]?[/yellow] Try FOCI scope expansion for "
            f"[bold]{required_scope}[/bold] and re-run?",
            default=True,
        )
    except (EOFError, KeyboardInterrupt):
        return None
    if not answered_yes:
        return None

    console.print(f"  [dim]→ Attempting FOCI expansion for {required_scope}…[/dim]")
    exchange = try_acquire_scope(store, required_scope)

    if exchange.status != "granted":
        note_map = {
            "consent_required": (
                "No FOCI client has admin consent for this scope on this "
                "tenant. Requires an app registration with the role granted."
            ),
            "invalid_grant": (
                "FOCI RT is dead (expired/revoked/CA-blocked). Re-authenticate "
                "via `acquire entra device_code` / `interactive`."
            ),
            "no_rt": "No FOCI RT — nothing to expand.",
            "unknown": f"AAD returned no grant. Last error: {exchange.last_error}",
        }
        console.print(
            f"  [red]✗[/red] FOCI expansion did not grant [bold]{required_scope}[/bold] "
            f"([bold]{exchange.status}[/bold]).\n"
            f"    [dim]{note_map.get(exchange.status, exchange.last_error)}[/dim]"
        )
        return None

    # Grant! Persist the enriched store back to the credential, then re-run.
    try:
        state.transport.update_credential(
            state.active_credential_id,
            secret_data=json.dumps({"token_store": store.to_dict()}),
        )
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Scope granted but persist failed: {e}")

    console.print(
        f"  [green]✓[/green] FOCI granted [bold]{required_scope}[/bold] — "
        "re-running technique with new scope…"
    )
    try:
        return state.transport.run_technique(
            technique_id,
            params=params if params else None,
            credential_id=state.active_credential_id,
            extra_providers=state._extra_providers or None,
            auto_scope=False,  # never chain a second retry
        )
    except Exception as e:
        console.print(f"  [red]✗[/red] Re-run raised: {e}")
        return None


def cmd_run(state: ShellState, args: list[str]) -> None:
    """Run a technique: run <technique_id> [--safe] [--param key=value ...]."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    if not args:
        console.print("  Usage: run <technique_id> [--safe] [--param key=value]", style="yellow")
        return

    technique_id = args[0]

    # --------------------------------------------------------
    # Parse parameters from remaining args.
    # Supports:
    #   1. --param key=value
    #   2. direct key=value
    # --------------------------------------------------------
    params: dict[str, str] = {}
    note = None
    # OPSEC-sensitive engagements can disable the semi-automatic FOCI
    # scope expansion by passing --no-auto-scope.
    auto_scope = True
    safe_mode = False
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--param":
            if i + 1 >= len(args) or "=" not in args[i + 1]:
                console.print("  [yellow]--param requires key=value[/yellow] — see `help run`")
                return
            kv = args[i + 1]
            k, v = kv.split("=", 1)
            params[k.strip()] = v.strip()
            i += 2
        elif arg == "--note":
            if i + 1 >= len(args):
                console.print("  [yellow]--note requires a value[/yellow] — see `help run`")
                return
            note = args[i + 1]
            i += 2
        elif arg == "--safe":
            safe_mode = True
            i += 1
        elif arg == "--no-auto-scope":
            auto_scope = False
            i += 1
        elif "=" in arg and not arg.startswith("-"):
            k, v = arg.split("=", 1)
            params[k.strip()] = v.strip()
            i += 1
        elif arg.startswith("--"):
            console.print(f"  [yellow]Unknown flag: {arg}[/yellow] — see `help run`")
            return
        else:
            console.print(f"  [yellow]Unexpected argument: {arg}[/yellow] — see `help run`")
            return

    if note:
        params["_run_note"] = note

    # ── Validate check-only availability before the technique can run ───────
    registered = state.loader.get(technique_id) if state.loader else None
    if safe_mode and (registered is None or not registered.metadata.safe_mode_available):
        console.print(
            f"  [yellow]{technique_id} does not support --safe[/yellow] "
            "— run it without the flag or choose a technique that advertises check-only mode."
        )
        return

    # ── Parameter hint / interactive picker for missing required params ─────
    if registered and registered.metadata.parameters:
        missing = [p for p in registered.metadata.parameters if p.required and p.name not in params]
        for p in list(missing):
            picker_cfg = _LOOT_PICKERS.get((technique_id, p.name))
            file_cfg = _FILE_PICKERS.get((technique_id, p.name))
            if picker_cfg:
                value = _loot_pick(
                    state,
                    picker_cfg["loot_technique"],
                    picker_cfg["value_col"],
                    picker_cfg["display_cols"],
                    picker_cfg.get("state_col"),
                )
                if value:
                    params[p.name] = value
                    missing.remove(p)
            elif file_cfg:
                value = _file_pick(
                    file_cfg["directory"],
                    file_cfg["extension"],
                    file_cfg["label"],
                )
                if value:
                    params[p.name] = value
                    missing.remove(p)
            else:
                # Plain inline prompt for other missing params
                value = _prompt_param(p.name, p.example)
                if value:
                    params[p.name] = value
                    missing.remove(p)

        if missing:
            names = ", ".join(f"[bold yellow]{p.name}[/bold yellow]" for p in missing)
            console.print(f"  [yellow]⚠[/yellow]  Required parameter(s) not provided: {names}")
            parts = " ".join(f"{p.name}={p.example or '<value>'}" for p in missing)
            console.print(f"  [dim]Usage: run {technique_id} {parts}[/dim]")
            return

    # ── Auto-pivot entra → azure when technique requires it ─────────────────
    # If the active credential is entra and the technique supports azure (but
    # not entra), try to restore the ARM pivot before running so the user
    # doesn't need to manually `acquire entra arm` on every session start.
    if state.loader and state.active_credential_id is not None:
        _active_creds = state.transport.list_credentials() if state.transport else []
        _cred_info = next(
            (c for c in _active_creds if c.get("id") == state.active_credential_id), None
        )
        if _cred_info and _cred_info.get("provider") == "entra":
            _registered = state.loader.get(technique_id)
            if _registered:
                _allowed = set(_registered.metadata.providers)
                if (
                    "azure" in _allowed
                    and "entra" not in _allowed
                    and "azure" not in state._extra_providers
                ):
                    _try_restore_arm_pivot(state)

    # ── Run with a live spinner so operators see elapsed time tick ──────────
    # run_technique() is blocking — we run it in a worker thread so the
    # main thread can drive Rich Live updates and show real elapsed time.
    import threading
    import time as _time

    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text as _Text

    from quantum_mechanic.core.telemetry import TelemetryLevel, TelemetryType

    start_ts = _time.monotonic()
    _result: list = [None]
    _exc: list = [None]
    event_queue: queue.Queue = queue.Queue()

    def _worker() -> None:
        try:
            _result[0] = state.transport.run_technique(
                technique_id,
                safe_mode=safe_mode,
                params=params if params else None,
                credential_id=state.active_credential_id,
                on_event=lambda e: event_queue.put(e),
                extra_providers=state._extra_providers or None,
            )
        except Exception as e:
            _exc[0] = e

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    with Live("", refresh_per_second=8, transient=True) as live:
        while worker.is_alive() or not event_queue.empty():
            # 1. Drain the event queue and print messages immediately
            while not event_queue.empty():
                try:
                    event = event_queue.get_nowait()
                    # We print to the live console so it doesn't break the spinner
                    if event.event_type == TelemetryType.LOG:
                        color = "white"
                        if event.level == TelemetryLevel.SUCCESS:
                            color = "green"
                        elif event.level == TelemetryLevel.WARNING:
                            color = "yellow"
                        elif event.level == TelemetryLevel.ERROR:
                            color = "red"

                        prefix = "    "
                        live.console.print(f"{prefix}[{color}]{event.message}[/{color}]")
                    elif event.event_type == TelemetryType.DISCOVERY:
                        live.console.print(
                            f"    [bold green]✓[/bold green] Discovered: [dim]{event.message}[/dim]"
                        )
                    elif event.event_type == TelemetryType.FINDING:
                        live.console.print(
                            f"    [bold red]![/bold red] Finding: [bold]{event.message}[/bold]"
                        )
                except queue.Empty:
                    break

            # 2. Update the spinner
            elapsed = _time.monotonic() - start_ts
            txt = _Text()
            txt.append("  ")
            txt.append(f"running {technique_id}", style="bold cyan")
            txt.append(f"  {elapsed:.1f}s elapsed", style="dim")
            live.update(Spinner("dots", text=txt))
            _time.sleep(0.05)

    worker.join()
    if _exc[0] is not None:
        raise _exc[0]

    # ── Semi-automatic FOCI scope retry (Task #3) ───────────────────────────
    # If the technique came back denied with a specific required_scope and
    # the active cred is an entra store with a FOCI RT, offer to expand
    # the scope and re-run once. We do this at the shell layer (rather than
    # inside the runner's worker thread) so the Live spinner is fully torn
    # down before we block on operator input.
    if auto_scope:
        retried = _maybe_offer_scope_retry(state, _result[0], technique_id, params)
        if retried is not None:
            _result[0] = retried

    formatters.format_technique_result(_result[0])


def cmd_techniques(state: ShellState, args: list[str]) -> None:
    """List available techniques, with filtering and search.

    Flags:
        --all                 Ignore active-provider filtering
        --tactic <name>       Filter by ATT&CK tactic (discovery, escalation, etc.)
        --provider <name>     Override active provider (aws, azure, gcp, oci, entra)
        --safe / --unsafe     Filter by safety classification
        <substring> [...]     Positional substring search across id and description
                              (AND semantics — all substrings must match)
    """
    # Parse flags
    show_all = "--all" in args
    safe_only = "--safe" in args
    unsafe_only = "--unsafe" in args

    tactic_filter: str | None = None
    provider_override: str | None = None
    substring_terms: list[str] = []

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--tactic" and i + 1 < len(args):
            tactic_filter = args[i + 1]
            i += 2
            continue
        if a == "--provider" and i + 1 < len(args):
            provider_override = args[i + 1]
            i += 2
            continue
        if a in ("--all", "--safe", "--unsafe"):
            i += 1
            continue
        if a.startswith("--"):
            console.print(f"  [yellow]Unknown flag: {a}[/yellow] — see `help techniques`")
            i += 1
            continue
        # positional → substring search term
        substring_terms.append(a.lower())
        i += 1

    # Resolve which provider to filter by
    active_provider = None
    if (
        not show_all
        and provider_override is None
        and state.transport
        and state.active_credential_id
    ):
        creds = state.transport.list_credentials()
        cred = next((c for c in creds if c.get("id") == state.active_credential_id), None)
        if cred:
            active_provider = cred.get("provider")

    effective_provider = provider_override or (None if show_all else active_provider)

    if state.transport is not None:
        all_techniques = list(state.transport.list_techniques(provider=effective_provider))
    else:
        all_techniques = [r.metadata for r in state.loader.list_all()]

    # Apply secondary filters (tactic, safe/unsafe, substring) client-side
    def keep(m) -> bool:
        if tactic_filter and m.tactic != tactic_filter:
            return False
        if safe_only and not m.safe:
            return False
        if unsafe_only and m.safe:
            return False
        if substring_terms:
            haystack = f"{m.id} {m.description}".lower()
            if not all(term in haystack for term in substring_terms):
                return False
        return True

    filtered = [m for m in all_techniques if keep(m)]

    from quantum_mechanic.core.loader import RegisteredTechnique

    wrapped = [
        RegisteredTechnique(metadata=m, function=lambda _: None, module_path="") for m in filtered
    ]
    formatters.format_techniques_list(wrapped)


def cmd_loot(state: ShellState, args: list[str]) -> None:
    """Display saved loot from previous technique runs: loot [technique_id]"""
    from pathlib import Path

    from rich import box
    from rich.table import Table

    if state.workspace is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    ws_db = Path(state.workspace.db_path)
    loot_root = ws_db.parent / ws_db.stem / "loot"

    if not loot_root.exists():
        console.print("  [dim]No loot found in this workspace.[/dim]")
        return

    # If a specific technique is given, render just that one
    if args:
        target_id = args[0].strip("/")
        loot_dir = loot_root / target_id
        if not loot_dir.exists():
            console.print(f"  [red]✗[/red] No loot for '{target_id}'.")
            return

        if target_id == "discovery/entra_enum_conditional_access_policies":
            _interactive_ca_policies_viewer(loot_dir, state.workspace)
            return

        pager_ctx = (
            console.pager(styles=True) if os.environ.get("TERM") != "dumb" else nullcontext()
        )
        with pager_ctx:
            _render_loot_dir(loot_dir, target_id)
        return

    # Default view: Show a summary table of techniques that have loot
    csv_files = sorted(loot_root.rglob("loot.csv"))
    if not csv_files:
        console.print("  [dim]No loot.csv files found.[/dim]")
        return

    summary = Table(title="Loot Summary", box=box.ROUNDED, border_style="dim")
    summary.add_column("Technique ID", style="bold cyan")
    summary.add_column("Rows", justify="right", style="green")
    summary.add_column("Last Updated", style="dim")

    for csv_path in csv_files:
        rel = csv_path.parent.relative_to(loot_root)
        tech_id = str(rel)
        try:
            with csv_path.open(newline="", encoding="utf-8") as fh:
                row_count = sum(1 for _ in fh) - 1  # skip header
            mtime = Path(csv_path).stat().st_mtime
            from datetime import datetime

            dt = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            summary.add_row(tech_id, str(max(0, row_count)), dt)
        except Exception:
            continue

    console.print(summary)
    console.print("  [dim]Use 'loot <id>' to view full results for a technique.[/dim]")


def _render_loot_dir(loot_dir, tech_id: str) -> None:
    """Render a single loot directory inline."""
    import csv
    import importlib
    from pathlib import Path

    from rich import box
    from rich.table import Table

    csv_path = Path(loot_dir) / "loot.csv"
    if not csv_path.exists():
        console.print(
            f"  [yellow]⚠[/yellow] Loot directory exists but 'loot.csv' is missing for {tech_id}"
        )
        return

    try:
        with csv_path.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
            fieldnames = list(reader.fieldnames or [])
    except Exception as e:
        console.print(f"  [red]✗[/red] Could not read {csv_path}: {e}")
        return

    # If the technique module has a newer LOOT_SCHEMA, merge its columns in.
    try:
        mod_path = f"quantum_mechanic.techniques.{tech_id.replace('/', '.')}"
        mod = importlib.import_module(mod_path)
        schema = getattr(mod, "LOOT_SCHEMA", None)
        if schema:
            schema_keys = [entry[0] for entry in schema]
            for key in schema_keys:
                if key not in fieldnames:
                    fieldnames.append(key)
    except Exception:
        pass

    if fieldnames:
        key_col = fieldnames[0]
        keyed: dict = {}
        for row in rows:
            keyed[row.get(key_col, "")] = row
        rows = list(keyed.values())

    console.print(f"  [bold cyan]{tech_id}[/bold cyan]  [dim]({len(rows)} row(s))[/dim]")

    if not rows:
        console.print("  [dim]  (no data rows)[/dim]")
        return

    table = Table(box=box.ROUNDED, border_style="dim")
    for col in fieldnames:
        table.add_column(col)

    for row in rows:
        table.add_row(*[row.get(f, "") for f in fieldnames])

    console.print(table)


def _interactive_ca_policies_viewer(loot_dir, workspace: Workspace | Path | None = None) -> None:
    """Render an interactive menu to inspect Conditional Access policies from loot."""
    import csv
    from pathlib import Path

    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table

    from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
        load_loot_mappings,
    )

    csv_path = Path(loot_dir) / "loot.csv"
    if not csv_path.exists():
        console.print("  [red]✗[/red] loot.csv not found.")
        return

    try:
        with csv_path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except Exception as e:
        console.print(f"  [red]✗[/red] Failed to read loot.csv: {e}")
        return

    if not rows:
        console.print("  [dim]No policies in loot.[/dim]")
        return

    # Load mapping for on-the-fly GUID resolution
    mapping = load_loot_mappings(workspace) if workspace else {}

    console.print(
        f"  [bold cyan]discovery/entra_enum_conditional_access_policies[/bold cyan] [dim]({len(rows)} policies)[/dim]\n"
    )

    def render_summary_table():
        summary = Table(box=box.ROUNDED, border_style="dim")
        summary.add_column("#", style="bold cyan", width=4)
        summary.add_column("Policy Name", style="bold white")
        summary.add_column("State", style="bold")
        summary.add_column("Access Controls", style="yellow")

        for i, row in enumerate(rows, 1):
            state = row.get("state", "unknown")
            state_style = (
                "green"
                if state == "enabled"
                else ("yellow" if "report" in state.lower() else "dim")
            )
            summary.add_row(
                str(i),
                row.get("display_name", "—"),
                f"[{state_style}]{state}[/{state_style}]",
                row.get("grant_controls", "—"),
            )
        console.print(summary)

    render_summary_table()

    while True:
        try:
            choice = input(
                "\n  Select a policy number to view detailed rules & bypass guidance (or type 'list' to show table, press Enter to exit) > "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break

        if not choice:
            break

        if choice.lower() in ["list", "l", "table", "show", "help", "?", "h"]:
            render_summary_table()
            continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(rows):
                p = rows[idx]

                # Helper to clean and resolve GUIDs in a value
                def clean_val(val_str):
                    if not val_str or val_str == "None":
                        return "None"
                    parts = [x.strip() for x in val_str.split(",") if x.strip()]
                    resolved = []
                    for pt in parts:
                        resolved.append(mapping.get(pt.lower(), mapping.get(pt, pt)))
                    return ", ".join(resolved)

                # Format detailed inclusions & exclusions
                incls = []
                inc_users = clean_val(p.get("included_users"))
                inc_groups = clean_val(p.get("included_groups"))
                inc_roles = clean_val(p.get("included_roles"))
                inc_apps = clean_val(p.get("included_apps"))
                inc_platforms = clean_val(p.get("included_platforms"))
                inc_locations = clean_val(p.get("included_locations"))
                client_apps_str = clean_val(p.get("client_app_types"))

                if inc_users != "None":
                    incls.append(f"[bold]Users:[/bold] {inc_users}")
                if inc_groups != "None" and inc_groups != "0":
                    incls.append(f"[bold]Groups:[/bold] {inc_groups}")
                if inc_roles != "None":
                    incls.append(f"[bold]Roles:[/bold] {inc_roles}")
                if inc_apps != "None" and inc_apps != "0":
                    incls.append(f"[bold]Applications:[/bold] {inc_apps}")
                if inc_platforms != "None" and inc_platforms != "All":
                    incls.append(f"[bold]Platforms:[/bold] {inc_platforms}")
                if inc_locations != "None" and inc_locations != "All":
                    incls.append(f"[bold]Locations:[/bold] {inc_locations}")
                if client_apps_str != "None" and client_apps_str != "All":
                    incls.append(f"[bold]Client Apps:[/bold] {client_apps_str}")

                excls = []
                exc_users = clean_val(p.get("excluded_users"))
                exc_groups = clean_val(p.get("excluded_groups"))
                exc_roles = clean_val(p.get("excluded_roles"))
                exc_apps = clean_val(p.get("excluded_apps"))
                exc_platforms = clean_val(p.get("exclude_platforms"))
                exc_locations = clean_val(p.get("excluded_locations"))

                if exc_users != "None":
                    excls.append(f"[bold]Users:[/bold] {exc_users}")
                if exc_groups != "None":
                    excls.append(f"[bold]Groups:[/bold] {exc_groups}")
                if exc_roles != "None":
                    excls.append(f"[bold]Roles:[/bold] {exc_roles}")
                if exc_apps != "None":
                    excls.append(f"[bold]Applications:[/bold] {exc_apps}")
                if exc_platforms != "None":
                    excls.append(f"[bold]Platforms:[/bold] {exc_platforms}")
                if exc_locations != "None":
                    excls.append(f"[bold]Locations:[/bold] {exc_locations}")

                # Analyze policy for bypass opportunities
                bypass_tips = []
                state_val = p.get("state", "")
                controls = p.get("grant_controls", "")

                if state_val == "disabled":
                    bypass_tips.append(
                        f"[bold yellow]• Policy is disabled.[/bold yellow] The configured controls ({controls}) are not active."
                    )
                elif "report" in state_val.lower():
                    bypass_tips.append(
                        f"[bold yellow]• Policy is in Report-Only mode.[/bold yellow] Its controls ({controls}) are not enforced."
                    )

                # Specific exclusions (resolving names at display time)
                for u in [
                    x.strip()
                    for x in p.get("excluded_users", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    u_res = mapping.get(u.lower(), mapping.get(u, u))
                    bypass_tips.append(
                        f"[bold red]• Excluded User:[/bold red] User '{u_res}' is excluded. Authenticating as this user bypasses controls ({controls})."
                    )
                for g in [
                    x.strip()
                    for x in p.get("excluded_groups", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    g_res = mapping.get(g.lower(), mapping.get(g, g))
                    bypass_tips.append(
                        f"[bold red]• Excluded Group:[/bold red] Group '{g_res}' is excluded. Members bypass controls ({controls}). Target group members or add compromised users to this group."
                    )
                for r in [
                    x.strip()
                    for x in p.get("excluded_roles", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    r_res = mapping.get(r.lower(), mapping.get(r, r))
                    bypass_tips.append(
                        f"[bold red]• Excluded Role:[/bold red] Role '{r_res}' is excluded. Principals with this role bypass controls ({controls})."
                    )
                for a in [
                    x.strip()
                    for x in p.get("excluded_apps", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    a_res = mapping.get(a.lower(), mapping.get(a, a))
                    bypass_tips.append(
                        f"[bold red]• Excluded App:[/bold red] App '{a_res}' is excluded. Access via this app bypasses controls ({controls})."
                    )
                for pl in [
                    x.strip()
                    for x in p.get("exclude_platforms", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    pl_res = mapping.get(pl.lower(), mapping.get(pl, pl))
                    bypass_tips.append(
                        f"[bold red]• Excluded Platform:[/bold red] Platform '{pl_res}' is excluded. Spoofing User-Agent to this platform bypasses controls ({controls})."
                    )
                for loc in [
                    x.strip()
                    for x in p.get("excluded_locations", "").split(",")
                    if x.strip() and x.strip() != "None"
                ]:
                    loc_res = mapping.get(loc.lower(), mapping.get(loc, loc))
                    bypass_tips.append(
                        f"[bold red]• Excluded Location:[/bold red] Location '{loc_res}' is excluded. Access from this network bypasses controls ({controls})."
                    )

                client_apps = [
                    x.strip().lower() for x in p.get("client_app_types", "").split(",") if x.strip()
                ]
                if "exchangeactivesync" in client_apps or "other" in client_apps:
                    legacy = [c for c in client_apps if c in ["exchangeactivesync", "other"]]
                    bypass_tips.append(
                        f"[bold yellow]• Legacy Auth Allowed:[/bold yellow] Legacy client type ({', '.join(legacy)}) allowed. Bypasses modern MFA."
                    )

                guidance_tips = list(bypass_tips)
                from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
                    explain_controls,
                )

                for exp in explain_controls(controls):
                    guidance_tips.append(f"[bold cyan]• Control Explanation:[/bold cyan] {exp}")

                guidance_str = (
                    "\n".join(guidance_tips)
                    if guidance_tips
                    else "No direct exclusion bypasses identified."
                )

                detail_group = Group(
                    f"[bold white]State:[/bold white] {p.get('state', 'unknown')}",
                    f"[bold white]Access Controls:[/bold white] {controls}",
                    "",
                    "[bold cyan]Inclusions:[/bold cyan]",
                    *([f"  {line}" for line in incls] if incls else ["  None"]),
                    "",
                    "[bold red]Exclusions:[/bold red]",
                    *([f"  {line}" for line in excls] if excls else ["  None"]),
                    "",
                    "[bold yellow]Bypass & Penetration Testing Guidance:[/bold yellow]",
                    guidance_str,
                )

                console.print(
                    Panel(
                        detail_group,
                        title=f"[bold white]Policy: {p.get('display_name', '—')}[/bold white]",
                        border_style="cyan",
                        box=box.DOUBLE,
                    )
                )
            else:
                console.print(f"  [red]✗[/red] Invalid policy number (must be 1-{len(rows)}).")
        except ValueError:
            console.print("  [red]✗[/red] Please enter a valid number.")


def cmd_check_ca_bypasses(state: ShellState, args: list[str]) -> None:
    """Analyze Conditional Access policy database evidence/loot for bypass opportunities: check-ca-bypasses"""
    import csv
    import json
    from pathlib import Path

    from rich import box
    from rich.panel import Panel
    from rich.table import Table

    if state.workspace is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    policies = []

    # 1. Try fetching from SQLite Evidence table first (newest record)
    try:
        evidence_list = state.workspace.list_evidence()
        # Find the latest evidence row for the CA policy enum technique
        ca_evidence = None
        for ev in reversed(evidence_list):
            if ev.get("technique_id") == "discovery/entra_enum_conditional_access_policies":
                ca_evidence = ev
                break

        if ca_evidence and ca_evidence.get("output_json"):
            payload = json.loads(ca_evidence["output_json"])
            policies = payload.get("policies", [])
    except Exception as e:
        logger.debug("Failed to fetch CA policies from DB evidence: %s", e)

    # 2. Fall back to loot.csv if DB evidence was empty/unavailable
    if not policies:
        ws_db = Path(state.workspace.db_path)
        loot_dir = (
            ws_db.parent
            / ws_db.stem
            / "loot"
            / "discovery"
            / "entra_enum_conditional_access_policies"
        )
        csv_path = loot_dir / "loot.csv"

        if csv_path.exists():
            try:
                with csv_path.open(newline="", encoding="utf-8") as fh:
                    policies = list(csv.DictReader(fh))
            except Exception as e:
                console.print(f"  [red]✗[/red] Failed to read loot.csv: {e}")
                return

    if not policies:
        console.print("  [red]✗[/red] No Conditional Access policy data found in database or loot.")
        console.print(
            "    Please run the discovery technique first: [cyan]run discovery/entra_enum_conditional_access_policies[/cyan]"
        )
        return

    # Load mapping for on-the-fly GUID resolution
    from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
        load_loot_mappings,
    )

    mapping = load_loot_mappings(state.workspace) if state.workspace else {}

    # Helper to coerce list or comma-separated string
    def get_list(val: Any) -> list[str]:
        if not val:
            return []
        if isinstance(val, list):
            return [str(x) for x in val if x]
        if isinstance(val, str):
            return [x.strip() for x in val.split(",") if x.strip() and x.strip() != "None"]
        return []

    # Bypasses to aggregate
    excluded_identities: dict[str, list[tuple[str, str]]] = {}
    app_exclusions: dict[str, list[tuple[str, str]]] = {}
    platform_exclusions: dict[str, list[tuple[str, str]]] = {}
    location_exclusions: dict[str, list[tuple[str, str]]] = {}
    legacy_auth_policies: list[tuple[str, list[str], str]] = []
    disabled_policies: list[tuple[str, str, str]] = []

    for p in policies:
        name = p.get("display_name") or p.get("displayName") or "Untitled"
        p_state = p.get("state")
        controls = p.get("grant_controls") or p.get("grantControls") or "None"
        if isinstance(controls, list):
            controls = ", ".join(controls)

        # Inactive policies
        if p_state == "disabled" or "report" in str(p_state).lower():
            disabled_policies.append((name, str(p_state), controls))
            continue

        # Aggregation 1: Excluded Identities
        for u in get_list(p.get("excluded_users")):
            u_res = mapping.get(u.lower(), mapping.get(u, u))
            excluded_identities.setdefault(u_res, []).append((name, controls))
        for g in get_list(p.get("excluded_groups")):
            g_res = mapping.get(g.lower(), mapping.get(g, g))
            excluded_identities.setdefault(f"Group: {g_res}", []).append((name, controls))
        for r in get_list(p.get("excluded_roles")):
            r_res = mapping.get(r.lower(), mapping.get(r, r))
            excluded_identities.setdefault(f"Role: {r_res}", []).append((name, controls))

        # Aggregation 2: Application Exclusions
        for a in get_list(p.get("excluded_apps") or p.get("excludedApplications")):
            a_res = mapping.get(a.lower(), mapping.get(a, a))
            app_exclusions.setdefault(a_res, []).append((name, controls))

        # Aggregation 3: Platform Exclusions
        for pl in get_list(p.get("exclude_platforms") or p.get("excludePlatforms")):
            pl_res = mapping.get(pl.lower(), mapping.get(pl, pl))
            platform_exclusions.setdefault(pl_res, []).append((name, controls))

        # Aggregation 4: Location Exclusions
        for loc in get_list(p.get("excluded_locations") or p.get("excludedLocations")):
            loc_res = mapping.get(loc.lower(), mapping.get(loc, loc))
            location_exclusions.setdefault(loc_res, []).append((name, controls))

        # Aggregation 5: Legacy Authentication Allowed
        client_apps = [
            x.lower() for x in get_list(p.get("client_app_types") or p.get("clientAppTypes"))
        ]
        if "exchangeactivesync" in client_apps or "other" in client_apps:
            legacy = [c for c in client_apps if c in ["exchangeactivesync", "other"]]
            legacy_auth_policies.append((name, legacy, controls))

    # Display results!
    console.print(
        "\n[bold yellow]================================================================[/bold yellow]"
    )
    console.print(
        "[bold yellow]       CONDITIONAL ACCESS AGGREGATED BYPASS OPPORTUNITIES       [/bold yellow]"
    )
    console.print(
        "[bold yellow]================================================================[/bold yellow]"
    )

    # 1. Identity Exclusions
    if excluded_identities:
        tbl = Table(
            title="Exclusions by Identity (Users / Groups / Roles)",
            box=box.ROUNDED,
            border_style="red",
        )
        tbl.add_column("Excluded Identity", style="bold white")
        tbl.add_column("Bypassed Policies & Controls", style="cyan")
        for ident, bypasses in sorted(excluded_identities.items()):
            b_strs = [f"'{p_name}' ({ctrls})" for p_name, ctrls in bypasses]
            tbl.add_row(ident, "\n".join(b_strs))
        console.print(tbl)
    else:
        console.print("\n  [green]✓[/green] No active user/group/role exclusions identified.")

    # 2. Location Exclusions
    if location_exclusions:
        tbl = Table(
            title="Exclusions by Named Location / IP Range", box=box.ROUNDED, border_style="yellow"
        )
        tbl.add_column("Excluded Location", style="bold white")
        tbl.add_column("Bypassed Policies & Controls", style="cyan")
        for loc, bypasses in sorted(location_exclusions.items()):
            b_strs = [f"'{p_name}' ({ctrls})" for p_name, ctrls in bypasses]
            tbl.add_row(loc, "\n".join(b_strs))
        console.print(tbl)

    # 3. Platform Exclusions
    if platform_exclusions:
        tbl = Table(title="Exclusions by Device Platform", box=box.ROUNDED, border_style="yellow")
        tbl.add_column("Excluded OS Platform", style="bold white")
        tbl.add_column("Bypassed Policies & Controls", style="cyan")
        for pl, bypasses in sorted(platform_exclusions.items()):
            b_strs = [f"'{p_name}' ({ctrls})" for p_name, ctrls in bypasses]
            tbl.add_row(pl, "\n".join(b_strs))
        console.print(tbl)

    # 4. App Exclusions
    if app_exclusions:
        tbl = Table(title="Exclusions by Cloud Application", box=box.ROUNDED, border_style="red")
        tbl.add_column("Excluded Application", style="bold white")
        tbl.add_column("Bypassed Policies & Controls", style="cyan")
        for app, bypasses in sorted(app_exclusions.items()):
            b_strs = [f"'{p_name}' ({ctrls})" for p_name, ctrls in bypasses]
            tbl.add_row(app, "\n".join(b_strs))
        console.print(tbl)

    # 5. Legacy Auth Allowed
    if legacy_auth_policies:
        tbl = Table(
            title="Legacy Authentication Protocol Gaps", box=box.ROUNDED, border_style="red"
        )
        tbl.add_column("Policy Name", style="bold white")
        tbl.add_column("Allowed Legacy Protocols", style="bold yellow")
        tbl.add_column("Grant Controls", style="cyan")
        for name, legacy, ctrls in legacy_auth_policies:
            tbl.add_row(name, ", ".join(legacy), ctrls)
        console.print(tbl)

    # 5.1 Rule-Based Bypass Detectors
    from quantum_mechanic.shell.ca_bypass_detectors import run_all_detectors

    detector_findings = run_all_detectors(policies)

    if detector_findings:
        tbl = Table(
            title="Known Bypass Pattern Detection", box=box.ROUNDED, border_style="magenta bold"
        )
        tbl.add_column("Severity", style="bold white")
        tbl.add_column("Vulnerability Type", style="bold red")
        tbl.add_column("Affected Policies", style="cyan")
        tbl.add_column("Description", style="yellow")

        for f in detector_findings:
            sev_color = (
                "red"
                if f.severity in ("CRITICAL", "HIGH")
                else "yellow"
                if f.severity == "MEDIUM"
                else "dim"
            )
            tbl.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.title,
                ", ".join(f.affected_policies),
                f.description,
            )
        console.print(tbl)

        # Attribution footer — credit the community researchers whose data
        # backs these detectors. Shown once per check-ca-bypasses run.
        from quantum_mechanic.providers.entra.refs import ATTRIBUTION_LINE, refs_status

        _status = refs_status()
        _foci_n = _status["graph_preconsent"]["foci_count"]
        _apps_n = _status["microsoft_apps"]["app_count"]
        console.print(
            f"  [dim]Reference data: {_foci_n} FOCI clients, "
            f"{_apps_n} first-party apps for name lookup. {ATTRIBUTION_LINE}[/dim]"
        )

    # 5.5 Cartesian Policy Sweep (MFA Bypass Matrix Analysis)
    # We build small representative domains from values referenced in policies
    # and run a Cartesian product sweep to find sign-in contexts allowed without MFA.
    import itertools

    def build_domain(key_inc: str, key_exc: str, default_val: str) -> list[str]:
        items = set()
        for p_dict in policies:
            raw_inc = (
                p_dict.get(key_inc)
                or p_dict.get(key_inc.replace("included", "include"))
                or p_dict.get(key_inc.replace("_", ""))
            )
            raw_exc = (
                p_dict.get(key_exc)
                or p_dict.get(key_exc.replace("excluded", "exclude"))
                or p_dict.get(key_exc.replace("_", ""))
            )
            for x in get_list(raw_inc):
                if x not in ["All", "None", "AllTrusted", "all"]:
                    items.add(x)
            for x in get_list(raw_exc):
                if x not in ["All", "None", "AllTrusted", "all"]:
                    items.add(x)
        res_list = sorted(list(items))
        if default_val not in res_list:
            res_list.append(default_val)
        return res_list

    domain_users = build_domain("included_users", "excluded_users", "generic_user@tenant.com")
    if "guest_user" not in domain_users:
        domain_users.append("guest_user")

    domain_groups = build_domain("included_groups", "excluded_groups", "None")
    domain_roles = build_domain("included_roles", "excluded_roles", "None")
    domain_apps = build_domain("included_apps", "excluded_apps", "generic_app")
    domain_platforms = ["windows", "macos", "ios", "android", "linux", "unknown"]
    domain_locations = build_domain("included_locations", "excluded_locations", "untrusted_ip")
    domain_clients = ["browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"]

    # New domains
    domain_sign_in_risk = ["none", "low", "medium", "high"]
    domain_user_risk = ["none", "low", "medium", "high"]
    domain_auth_flow = ["normal", "deviceCodeFlow", "authenticationTransfer"]

    def matches_val(val: str, includes: list[str], excludes: list[str]) -> bool:
        if "All" in excludes or val in excludes:
            return False
        if not includes or "None" in includes:
            return False
        if "All" in includes or val in includes:
            return True
        return False

    def matches_loc(val: str, includes: list[str], excludes: list[str]) -> bool:
        if "All" in excludes or val in excludes:
            return False
        for excl in excludes:
            if excl.split(" (")[0] in val:
                return False
        if not includes or "None" in includes:
            return False
        if "All" in includes:
            return True
        for incl in includes:
            if incl.split(" (")[0] in val:
                return True
        return False

    def matches_policy(
        p_dict: dict,
        u: str,
        g: str,
        r: str,
        app: str,
        platform: str,
        loc: str,
        client: str,
        sign_in_risk: str,
        user_risk: str,
        auth_flow: str,
    ) -> bool:
        # Resolve fields flexibly
        inc_u = get_list(p_dict.get("included_users") or p_dict.get("includeUsers"))
        exc_u = get_list(p_dict.get("excluded_users") or p_dict.get("excludeUsers"))
        inc_g = get_list(p_dict.get("included_groups") or p_dict.get("includeGroups"))
        exc_g = get_list(p_dict.get("excluded_groups") or p_dict.get("excludeGroups"))
        inc_r = get_list(p_dict.get("included_roles") or p_dict.get("includeRoles"))
        exc_r = get_list(p_dict.get("excluded_roles") or p_dict.get("excludeRoles"))

        # Exclusion is absolute
        if u in exc_u or g in exc_g or r in exc_r:
            return False

        user_matched = False
        if "All" in inc_u or u in inc_u or g in inc_g or r in inc_r:
            user_matched = True

        # Handle guest users
        if u == "guest_user":
            inc_guests = p_dict.get("include_guest_types", "")
            exc_guests = p_dict.get("exclude_guest_types", "")
            if exc_guests and exc_guests != "None":
                return False
            if inc_guests and inc_guests != "None":
                user_matched = True

        if not user_matched:
            return False

        inc_a = get_list(
            p_dict.get("included_apps")
            or p_dict.get("includeApplications")
            or p_dict.get("includedApplications")
        )
        exc_a = get_list(
            p_dict.get("excluded_apps")
            or p_dict.get("excludeApplications")
            or p_dict.get("excludedApplications")
        )

        # Expand Office365 to individual apps if targeted
        # Exchange Online, SharePoint Online, Teams, etc.
        o365_apps = ["00000002-0000-0ff1-ce00-000000000000", "00000003-0000-0ff1-ce00-000000000000"]
        if "Office365" in inc_a and app in o365_apps:
            inc_a.append(app)

        if not matches_val(app, inc_a, exc_a):
            return False

        inc_p = [
            x.lower()
            for x in get_list(
                p_dict.get("included_platforms")
                or p_dict.get("includePlatforms")
                or p_dict.get("includedPlatforms")
            )
        ]
        if not inc_p:
            inc_p = ["all"]
        exc_p = [
            x.lower()
            for x in get_list(
                p_dict.get("exclude_platforms")
                or p_dict.get("excludePlatforms")
                or p_dict.get("excludedPlatforms")
            )
        ]
        if not matches_val(platform.lower(), inc_p, exc_p):
            return False

        inc_l = get_list(
            p_dict.get("included_locations")
            or p_dict.get("includeLocations")
            or p_dict.get("includedLocations")
        )
        if not inc_l:
            inc_l = ["All"]
        exc_l = get_list(
            p_dict.get("excluded_locations")
            or p_dict.get("excludeLocations")
            or p_dict.get("excludedLocations")
        )
        if not matches_loc(loc, inc_l, exc_l):
            return False

        inc_c = [
            x.lower()
            for x in get_list(p_dict.get("client_app_types") or p_dict.get("clientAppTypes"))
        ]
        if not inc_c:
            inc_c = ["all"]
        if "all" not in inc_c and client.lower() not in inc_c:
            return False

        # Risk levels
        p_sign_in_risk = [x.lower() for x in get_list(p_dict.get("sign_in_risk_levels"))]
        if p_sign_in_risk and p_sign_in_risk != ["none"]:
            if sign_in_risk not in p_sign_in_risk:
                return False

        p_user_risk = [x.lower() for x in get_list(p_dict.get("user_risk_levels"))]
        if p_user_risk and p_user_risk != ["none"]:
            if user_risk not in p_user_risk:
                return False

        # Auth flows
        p_auth_flow = p_dict.get("auth_flows", "").lower()
        if p_auth_flow:
            if auth_flow not in p_auth_flow:
                return False

        return True

    sweep_gaps = []
    MAX_SWEEP = 500_000
    space_size = 1
    for d in [
        domain_users,
        domain_groups,
        domain_roles,
        domain_apps,
        domain_platforms,
        domain_locations,
        domain_clients,
        domain_sign_in_risk,
        domain_user_risk,
        domain_auth_flow,
    ]:
        space_size *= len(d)

    capped = space_size > MAX_SWEEP
    if capped:
        console.print(
            f"  [yellow]⚠[/yellow] Cartesian space is {space_size:,} combinations — capping sweep at {MAX_SWEEP:,} for performance."
        )

    evaluated = 0
    for combo in itertools.product(
        domain_users,
        domain_groups,
        domain_roles,
        domain_apps,
        domain_platforms,
        domain_locations,
        domain_clients,
        domain_sign_in_risk,
        domain_user_risk,
        domain_auth_flow,
    ):
        if evaluated >= MAX_SWEEP:
            break
        evaluated += 1
        u, g, r, app, platform, loc, client, sign_in_risk, user_risk, auth_flow = combo
        is_blocked = False
        matching_policies = []
        active_grants = []

        for p_dict in policies:
            p_state = p_dict.get("state")
            if p_state != "enabled":
                continue

            if matches_policy(
                p_dict, u, g, r, app, platform, loc, client, sign_in_risk, user_risk, auth_flow
            ):
                p_name = p_dict.get("display_name") or p_dict.get("displayName") or "Untitled"
                matching_policies.append(p_name)
                controls = p_dict.get("grant_controls") or p_dict.get("grantControls") or "None"
                grant_op = str(p_dict.get("grant_operator") or "OR").upper()
                if isinstance(controls, list):
                    controls = ", ".join(controls)
                controls_list = [x.strip() for x in controls.split(",") if x.strip()]

                if "block" in [c.lower() for c in controls_list]:
                    is_blocked = True
                    break
                active_grants.append((grant_op, controls_list))

        if not is_blocked:
            mfa_enforced = False
            for grant_op, controls_list in active_grants:
                mfa_in_policy = any(
                    "mfa" in c.lower() or "authstrength" in c.lower() for c in controls_list
                )
                if grant_op == "OR":
                    if mfa_in_policy and len(controls_list) == 1:
                        mfa_enforced = True
                        break
                elif grant_op == "AND":
                    if mfa_in_policy:
                        mfa_enforced = True
                        break

            if not mfa_enforced:
                sweep_gaps.append(
                    {
                        "user": u,
                        "group": g,
                        "role": r,
                        "app": app,
                        "platform": platform,
                        "location": loc,
                        "client": client,
                        "sign_in_risk": sign_in_risk,
                        "user_risk": user_risk,
                        "auth_flow": auth_flow,
                        "matching_policies": matching_policies,
                    }
                )

    if sweep_gaps:
        tbl = Table(
            title="MFA-Bypass Attack Paths (Matrix Sweep)", box=box.ROUNDED, border_style="red bold"
        )
        tbl.add_column("Target Identity (User/Group/Role)", style="bold white")
        tbl.add_column("Access Context (App / OS / Loc / Client)", style="yellow")
        tbl.add_column("Matching Policies (No MFA Enforced)", style="cyan")

        shown_unique = set()
        count = 0
        for gap in sweep_gaps:
            u_res = mapping.get(gap["user"].lower(), mapping.get(gap["user"], gap["user"]))
            g_res = mapping.get(gap["group"].lower(), mapping.get(gap["group"], gap["group"]))
            r_res = mapping.get(gap["role"].lower(), mapping.get(gap["role"], gap["role"]))

            ident_str = f"{u_res}"
            if g_res != "None":
                ident_str += f"\nGroup: {g_res}"
            if r_res != "None":
                ident_str += f"\nRole: {r_res}"

            ctx_str = f"App: {gap['app']}\nOS: {gap['platform']}\nLoc: {gap['location'].split(' (')[0]}\nClient: {gap['client']}"
            p_strs = ", ".join(gap["matching_policies"]) if gap["matching_policies"] else "None"

            unique_key = (ident_str, gap["app"], gap["platform"], gap["client"])
            if unique_key not in shown_unique:
                shown_unique.add(unique_key)
                tbl.add_row(ident_str, ctx_str, p_strs)
                count += 1
                if count >= 10:
                    break

        console.print(tbl)
        console.print(
            f"  [red]⚠️[/red] Discovered [bold red]{len(sweep_gaps)}[/bold red] total path combinations allowed without MFA (evaluated {evaluated:,} of {space_size:,}).\n"
        )
    else:
        console.print(
            f"\n  [green]✓[/green] No MFA-bypass paths identified via Cartesian sweep ({evaluated:,} combinations evaluated).\n"
        )

    # 6. Disabled or Report-Only Policies
    if disabled_policies:
        tbl = Table(title="Inactive / Non-Enforced Policies", box=box.ROUNDED, border_style="dim")
        tbl.add_column("Policy Name", style="bold white")
        tbl.add_column("State", style="bold yellow")
        tbl.add_column("Configured Controls", style="cyan")
        for name, state, ctrls in disabled_policies:
            tbl.add_row(name, state, ctrls)
        console.print(tbl)

    # ── Executive Summary ────────────────────────────────────────────────────
    n_critical = sum(1 for f in detector_findings if f.severity == "CRITICAL")
    n_high = sum(1 for f in detector_findings if f.severity == "HIGH")
    n_medium = sum(1 for f in detector_findings if f.severity == "MEDIUM")
    n_low = sum(1 for f in detector_findings if f.severity == "LOW")
    n_info = sum(1 for f in detector_findings if f.severity == "INFO")
    n_sweep = len(sweep_gaps)
    n_disabled = len(disabled_policies)

    summary_lines = [
        f"[red]CRITICAL:[/red] {n_critical}  [bold red]HIGH:[/bold red] {n_high}  [yellow]MEDIUM:[/yellow] {n_medium}  [dim]LOW:[/dim] {n_low}  [dim]INFO:[/dim] {n_info}",
        f"[red]MFA Bypass Paths:[/red] {n_sweep:,}  [dim]| Combinations Evaluated:[/dim] {evaluated:,} of {space_size:,}",
        f"[yellow]Inactive Policies:[/yellow] {n_disabled}  [dim]| Total Policies:[/dim] {len(policies)}",
    ]

    if n_critical > 0 or n_high > 0:
        summary_lines.append("")
        summary_lines.append(
            "[bold red]⚠ ACTION REQUIRED:[/bold red] Critical or High findings detected. Run [cyan]info check-ca-bypasses[/cyan] for remediation workflow."
        )

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold white]CA Gap Analysis — Executive Summary[/bold white]",
            border_style="bold green",
            padding=(1, 2),
        )
    )

    console.print(
        "\n[bold green]✓[/bold green] Analysis complete. Target these exclusions during credential mapping and lateral movement."
    )


def cmd_raw(state: ShellState, args: list[str]) -> None:
    """Show raw JSON data for an entity: raw <credential_id>."""
    # Only available in local mode for now since RemoteTransport doesn't expose raw data yet.
    if state.workspace is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    if not args:
        console.print("  Usage: raw <credential_id>", style="yellow")
        return

    try:
        cred_id = int(args[0])
        cred = state.workspace.get_credential(cred_id)
        if cred is None:
            console.print(f"  [red]✗[/red] Credential #{cred_id} not found.")
            return

        if cred.principal_id:
            principal = state.workspace.get_principal(cred.provider, cred.principal_id)
            if principal and principal.raw_data:
                formatters.format_raw(principal.raw_data)
                return

        formatters.format_raw(cred.raw_data)
    except ValueError:
        console.print(f"  [red]✗[/red] Invalid ID: {args[0]}")


def cmd_ask(state: ShellState, args: list[str]) -> None:
    """Ask the Quantum Mechanic RAG Agent for advice."""
    if not state.workspace:
        console.print("  [red]✗[/red] No workspace active. Run 'workspace create <name>'.")
        return

    if not args:
        console.print("  Usage: ask <question>", style="yellow")
        return

    question = " ".join(args)

    try:
        from rich.markdown import Markdown

        from quantum_mechanic.agent.orchestrator import AgentOrchestrator
    except ImportError:
        console.print("\n[red]✗ Agent Dependencies Missing[/red]")
        console.print("  The RAG Agent is an optional feature.")
        console.print("  To enable it, install the AI dependencies:")
        console.print("  [bold cyan]uv sync --extra agent[/bold cyan]")
        return

    with console.status("[cyan]Agent reasoning...[/cyan]"):
        try:
            agent = AgentOrchestrator(state.workspace)
            response = agent.ask(question)
        except Exception as e:
            if "api key" in str(e).lower() or "anthropic" in str(e).lower():
                console.print("\n[red]✗ Anthropic API Key Missing[/red]")
                console.print(
                    "  Please set the [bold cyan]ANTHROPIC_API_KEY[/bold cyan] environment variable."
                )
                return
            console.print(f"\n[red]✗ Agent Error:[/red] {e}")
            return

    console.print("\n[bold cyan]🧠 Quantum Mechanic Agent[/bold cyan]")
    console.print(Markdown(response))
    console.print()


def cmd_activity(state: ShellState, args: list[str]) -> None:
    """View the workspace activity log: activity [technique_id] [--level LEVEL] [--limit N]"""
    if state.workspace is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    opts = _parse_opts(args)
    limit = int(opts.get("limit", 50))
    level = opts.get("level")

    # Filter by tech ID if provided (first positional arg)
    tech_id = None
    if args and not args[0].startswith("--"):
        tech_id = args[0]

    logs = state.workspace.list_activity_log(technique_id=tech_id, level=level, limit=limit)

    if not logs:
        console.print("  [dim]No activity log entries found.[/dim]")
        return

    from rich import box
    from rich.table import Table

    pager_ctx = console.pager(styles=True) if os.environ.get("TERM") != "dumb" else nullcontext()
    with pager_ctx:
        tbl = Table(
            title=f"Activity Log - {state.workspace.name}", box=box.SIMPLE, header_style="bold cyan"
        )
        tbl.add_column("Timestamp", style="dim")
        tbl.add_column("Technique", style="cyan")
        tbl.add_column("Level")
        tbl.add_column("Message")

        _LEVEL_STYLES = {
            "DEBUG": "dim",
            "INFO": "white",
            "SUCCESS": "bold green",
            "WARNING": "bold yellow",
            "ERROR": "bold red",
        }

        # Reverse to show chronological order in the pager
        for log in reversed(logs):
            lvl = log["level"].upper()
            style = _LEVEL_STYLES.get(lvl, "white")
            ts = log["timestamp"][11:19]  # Show HH:MM:SS

            tbl.add_row(ts, log["technique_id"], f"[{style}]{lvl}[/{style}]", log["message"])

        console.print(tbl)


def _show_check_ca_bypasses_help() -> None:
    """Display comprehensive help for the check-ca-bypasses command."""
    from rich import box
    from rich.table import Table

    console.print("\n[bold white]COMMAND: check-ca-bypasses[/bold white]")
    console.print(
        "  [dim]Analyze Conditional Access policy database for bypass opportunities.[/dim]\n"
    )

    intel = [
        "[bold cyan]Category:[/bold cyan]   Post-Exploitation Analysis",
        "[bold cyan]Provider:[/bold cyan]   Entra ID (Azure AD)",
        "[bold cyan]Prereq:[/bold cyan]     run discovery/entra_enum_conditional_access_policies",
        "[bold cyan]MITRE ID:[/bold cyan]   T1556.006 (Modify Authentication Process: Conditional Access)",
    ]
    for line in intel:
        console.print(f"  {line}")
    console.print()

    console.print("[bold white]WORKFLOW[/bold white]")
    console.print("""
  [bold cyan]1.[/bold cyan] Enumerate policies (collects 25+ fields per policy from Graph API):
     [yellow]qm> run discovery/entra_enum_conditional_access_policies[/yellow]

  [bold cyan]2.[/bold cyan] Run the bypass analyzer:
     [yellow]qm> check-ca-bypasses[/yellow]

  [bold cyan]3.[/bold cyan] Review the output sections:
     • [bold white]Flat Exclusion Analysis[/bold white]  — Which users/groups/locations bypass each policy
     • [bold magenta]Known Bypass Pattern Detection[/bold magenta]  — 14 heuristic detectors (CRITICAL → INFO)
     • [bold red]MFA-Bypass Attack Paths[/bold red]  — Cartesian sweep of sign-in contexts without MFA
     • [dim]Inactive Policies[/dim]  — Report-only or disabled policies
     • [bold green]Executive Summary[/bold green]  — Finding counts by severity
""")

    console.print("[bold white]BYPASS DETECTORS (14 checks)[/bold white]\n")
    det_tbl = Table(box=box.SIMPLE, padding=(0, 2))
    det_tbl.add_column("Severity", style="bold")
    det_tbl.add_column("Detector", style="cyan")
    det_tbl.add_column("What It Catches")

    detectors = [
        (
            "CRITICAL",
            "Legacy Auth Allowed",
            "Policies allowing ExchangeActiveSync/Other without blocking",
        ),
        (
            "HIGH",
            "Device Code Flow Not Blocked",
            "No policy blocks deviceCodeFlow — phishing via device code",
        ),
        ("HIGH", "FOCI App Exclusion", "Excluded apps share token families with protected apps"),
        ("HIGH", "Break-Glass Over-Exclusion", "Accounts excluded from ALL enabled policies"),
        (
            "HIGH",
            "Vulnerable 'OR' Grant",
            "MFA + weaker control with OR operator — attacker picks the weak path",
        ),
        (
            "MEDIUM",
            "Weak MFA Strength",
            "Generic MFA instead of phishing-resistant Authentication Strength",
        ),
        (
            "MEDIUM",
            "Platform Gaps",
            "Policies targeting specific platforms — bypass via User-Agent spoofing",
        ),
        ("MEDIUM", "No Workload Identity CA", "No CA policies protect Service Principals"),
        ("MEDIUM", "Guest Coverage Gap", "All Users policy excludes guests without fallback"),
        ("MEDIUM", "Session Hijack Risk", "Persistent Browser: always without Token Protection"),
        ("MEDIUM", "Token Protection Missing", "No policy enables Secure Sign-In Session"),
        ("LOW", "Auth Transfer Not Blocked", "No policy blocks Authentication Transfer flow"),
        ("INFO", "Report-Only Policies", "Policies logging but not enforcing controls"),
        ("INFO", "Trusted Location Risk", "Broad 'AllTrusted' location exclusions"),
    ]
    for sev, name, desc in detectors:
        sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "dim"
        det_tbl.add_row(f"[{sev_color}]{sev}[/{sev_color}]", name, desc)
    console.print(det_tbl)

    console.print("\n[bold white]REMEDIATION PRIORITY[/bold white]")
    console.print("""
  [bold red]1. CRITICAL/HIGH:[/bold red] Fix immediately — these represent direct MFA bypass paths.
     • Block legacy auth globally with a dedicated CA policy
     • Block Device Code Flow via authentication flow conditions
     • Change 'OR' grant operators to 'AND' (Require ALL selected controls)
     • Audit break-glass account exclusions

  [bold yellow]2. MEDIUM:[/bold yellow] Fix in next sprint — these weaken the security posture.
     • Upgrade generic MFA to phishing-resistant Authentication Strength
     • Target 'Any device' instead of specific platforms
     • Enable Token Protection for critical apps
     • Create dedicated guest/external user policies

  [dim]3. LOW/INFO:[/dim] Track and review — informational findings.
     • Evaluate report-only policies for production readiness
     • Audit trusted location CIDR ranges
""")


def cmd_help(state: ShellState, args: list[str]) -> None:
    """Show available commands or technique documentation."""
    import importlib
    import inspect

    # No args → list commands from registry.
    if not args:
        from quantum_mechanic.shell import formatters

        formatters.format_help_menu(COMMANDS, command_help_registry=COMMAND_HELP)
        return

    target = args[0].strip("/")

    # 1. Resolve as a shell command first.
    if target in COMMAND_HELP:
        _render_command_help(COMMAND_HELP[target])
        return

    # 2. Built-in command documentation.
    if target == "check-ca-bypasses":
        _show_check_ca_bypasses_help()
        return

    # 3. Fall through to technique lookup.
    registered = state.loader.get(target)
    if registered is None:
        console.print(
            f"  [red]✗[/red] '{target}' is neither a shell command nor a registered technique. "
            "Try `help` for the command list or `techniques` for the technique list."
        )
        return

    # --- Existing technique-rendering code preserved verbatim below ---
    m = registered.metadata
    safe_label = (
        "[green]Safe (Read-Only)[/green]" if m.safe else "[red]Impact (Modifies State)[/red]"
    )

    console.print(f"\n[bold white]MODULE: {m.id}[/bold white]")
    console.print(f"  [dim]{m.description}[/dim]\n")

    intel = [
        f"[bold cyan]Tactic:[/bold cyan]    {m.tactic}",
        f"[bold cyan]MITRE ID:[/bold cyan]  {m.mitre_id or '—'}",
        f"[bold cyan]Providers:[/bold cyan] {', '.join(m.providers) if m.providers else 'unauthenticated'}",
        f"[bold cyan]Severity:[/bold cyan]  {m.severity.upper()}",
        f"[bold cyan]Risk Profile:[/bold cyan] {safe_label}",
    ]
    for line in intel:
        console.print(f"  {line}")

    console.print()

    if m.parameters:
        from rich.table import Table

        param_table = Table(box=None, padding=(0, 2), show_header=True)
        param_table.add_column("Option", style="bold yellow")
        param_table.add_column("Format", style="dim")
        param_table.add_column("Req", style="red")
        param_table.add_column("Description")

        for p in m.parameters:
            req_star = "*" if p.required else " "
            param_table.add_row(p.name, p.type.label, req_star, p.description)

        console.print("  [bold white]Operational Options:[/bold white]")
        console.print(param_table)
        console.print()

        console.print("  [bold white]Usage Examples:[/bold white]")
        console.print(f"    qm> run {m.id}")
        example_parts = [f"{p.name}={p.example}" for p in m.parameters if p.example]
        if example_parts:
            console.print(f"    qm> run {m.id} {' '.join(example_parts)}")
        console.print()

    try:
        mod = importlib.import_module(registered.module_path)
        src = inspect.getsource(mod)

        def _extract_block(src: str, start_marker: str) -> list[str]:
            idx = src.find(start_marker)
            if idx == -1:
                return []
            end = src.find("\n#\n", idx)
            block = src[idx : end if end != -1 else idx + 800]
            lines = []
            for ln in block.splitlines():
                stripped = ln.lstrip("# ").rstrip()
                lines.append(stripped)
            return lines

        params_lines = _extract_block(src, "# PARAMETERS")
        if params_lines and not m.parameters:
            console.print("[bold]Parameters (via --param key=value):[/bold]")
            for ln in params_lines[1:]:
                console.print(f"  {ln}")
            console.print()

        usage_lines = _extract_block(src, "# USAGE (interactive shell):")
        if usage_lines:
            console.print("[bold]Usage examples:[/bold]")
            for ln in usage_lines:
                if ln:
                    console.print(f"  [dim]{ln}[/dim]")
            console.print()
    except Exception:
        pass


def _render_command_help(h: CommandHelp) -> None:
    """Render a CommandHelp record as Rich output for `help <command>`."""
    from rich.table import Table

    console.print(f"\n[bold white]COMMAND: {h.name}[/bold white]")
    console.print(f"  [dim]{h.synopsis}[/dim]\n")
    console.print(f"  {h.description}\n")

    if h.subcommands:
        tbl = Table(box=None, padding=(0, 2), show_header=True)
        tbl.add_column("Subcommand", style="bold cyan")
        tbl.add_column("Args", style="dim")
        tbl.add_column("Description")
        for s in h.subcommands:
            tbl.add_row(s.name, s.args or "—", s.synopsis)
        console.print("  [bold]Subcommands:[/bold]")
        console.print(tbl)
        console.print()

    if h.flags:
        tbl = Table(box=None, padding=(0, 2), show_header=True)
        tbl.add_column("Flag", style="bold yellow")
        tbl.add_column("Value", style="dim")
        tbl.add_column("Description")
        for f in h.flags:
            tbl.add_row(f.name, f.value or "—", f.synopsis)
        console.print("  [bold]Flags:[/bold]")
        console.print(tbl)
        console.print()

    if h.examples:
        console.print("  [bold]Examples:[/bold]")
        for ex in h.examples:
            console.print(f"    qm> {ex}")
        console.print()


def cmd_report(state: ShellState, args: list[str]) -> None:
    """Render the engagement narrative inline in the terminal using Rich tables."""
    import json

    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree

    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace/connection. Load one first.")
        return

    pager_ctx = console.pager(styles=True) if os.environ.get("TERM") != "dumb" else nullcontext()
    with pager_ctx:
        transport = state.transport
        info = transport.workspace_info()
        ws_name = info.get("name", "Unknown Workspace")

        from datetime import UTC, datetime

        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        creds_all = transport.list_credentials()
        providers = (
            ", ".join(sorted({c.get("provider", "unknown").upper() for c in creds_all})) or "none"
        )

        console.print(
            Panel(
                f"[bold white]Attack Path — {ws_name}[/bold white]\n"
                f"[dim]Updated: {now_str}   Providers: {providers}[/dim]",
                style="blue",
            )
        )

        console.print("\n[bold cyan]Credential Chain[/bold cyan]")
        console.print("[dim]How each identity was obtained:[/dim]\n")
        if not creds_all:
            console.print("  [dim]No credentials loaded.[/dim]")
        else:
            children: dict[int | None, list] = {}
            for c in creds_all:
                children.setdefault(c.get("derived_from_id"), []).append(c)

            def _render_tree(tree_node, cred_id: int | None) -> None:
                for c in children.get(cred_id, []):
                    name = c.get("friendly_name") or c.get("credential_type", "unknown")
                    obtained_via = c.get("obtained_via")
                    obtained = f" ← {obtained_via}" if obtained_via else ""
                    status = c.get("status", "unknown")
                    status_style = (
                        "red"
                        if status == "expired"
                        else ("yellow" if status == "expiring" else "green")
                    )
                    label = (
                        f"[bold]#{c.get('id')}[/bold] [{status_style}]{c.get('provider', 'unknown').upper()}[/{status_style}] "
                        f"`{name}`[dim]{obtained}[/dim]"
                    )
                    branch = tree_node.add(label)
                    _render_tree(branch, c.get("id"))

            root_tree = Tree("[bold]Credentials[/bold]")
            _render_tree(root_tree, None)
            console.print(root_tree)

        console.print("\n[bold cyan]Technique Timeline[/bold cyan]")
        evidence_rows = transport.list_evidence()
        if not evidence_rows:
            console.print("  [dim]No activity recorded.[/dim]")
        else:
            tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            tbl.add_column("#", style="dim", width=4)
            tbl.add_column("Timestamp", width=16)
            tbl.add_column("Technique")
            tbl.add_column("Provider", width=8)
            tbl.add_column("Principal")

            # --------------------------------------------------------
            # Build a credential lookup map to resolve the principal
            # name when the technique output does not store it.
            # --------------------------------------------------------
            cred_map = {c.get("id"): c for c in creds_all if c.get("id") is not None}

            for i, row in enumerate(evidence_rows, 1):
                ts = str(row.get("timestamp", ""))[:16]
                tech = row.get("technique_id", "unknown")
                provider = "?"
                principal = "?"
                try:
                    data = json.loads(row.get("output_json", "{}"))
                    provider = (data.get("provider") or "?").upper()

                    # --------------------------------------------------------
                    # Extract principal identity from evidence output JSON,
                    # defaulting to credential metadata if not present.
                    # --------------------------------------------------------
                    raw_principal = (
                        data.get("principal")
                        or data.get("friendly_name")
                        or data.get("starting_principal")
                    )
                    if not raw_principal or raw_principal == "?":
                        c = cred_map.get(row.get("credential_id"))
                        if c:
                            raw_principal = c.get("friendly_name") or c.get("principal_id")

                    if raw_principal:
                        principal = str(raw_principal).split("/")[-1]
                    else:
                        principal = "?"
                except Exception:
                    pass
                tbl.add_row(str(i), ts, tech, provider, principal)

            console.print(tbl)

        console.print("\n[bold cyan]Findings[/bold cyan]")
        findings = transport.list_findings()
        if not findings:
            console.print("  [dim]No findings recorded yet.[/dim]")
        else:
            _SEV_STYLE = {
                "critical": ("🔴", "bold red"),
                "high": ("🟠", "bold yellow"),
                "medium": ("🟡", "yellow"),
                "low": ("🔵", "cyan"),
                "info": ("⚪", "dim"),
            }
            ftbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
            ftbl.add_column("ID", width=5)
            ftbl.add_column("Severity", width=10)
            ftbl.add_column("Finding")
            ftbl.add_column("Provider", width=8)
            ftbl.add_column("Technique")

            for f in sorted(
                findings,
                key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    x.get("severity", "info").lower(), 99
                ),
            ):
                fid = f.get("id", "?")
                sev = f.get("severity", "info").lower()
                emoji, style = _SEV_STYLE.get(sev, ("⚪", "dim"))
                ftbl.add_row(
                    f"F{fid:03d}" if isinstance(fid, int) else str(fid),
                    f"[{style}]{emoji} {sev.upper()}[/{style}]",
                    f.get("title", "Untitled"),
                    f.get("provider", "?").upper(),
                    f.get("technique_id", "?"),
                )
            console.print(ftbl)

        console.print()


def cmd_reload(state: ShellState, args: list[str]) -> None:
    """Hot-reload technique modules without restarting qm."""
    n = state.loader.reload_all()
    console.print(f"  [green]✓[/green] Reloaded — {n} technique(s) loaded.")


def cmd_playbook(state: ShellState, args: list[str]) -> None:
    """Manage and run playbooks: playbook [list|run <name>]"""
    playbook_dir = Path(__file__).parent.parent / "playbooks"

    if not args or args[0] == "list":
        if not playbook_dir.exists():
            console.print("  [dim]No playbooks found.[/dim]")
            return

        from rich.table import Table

        tbl = Table(title="Available Playbooks", box=None)
        tbl.add_column("Name", style="bold cyan")
        tbl.add_column("Description", style="dim")

        for p in sorted(playbook_dir.glob("*.yaml")):
            try:
                import yaml

                with p.open("r") as f:
                    data = yaml.safe_load(f)
                    tbl.add_row(p.stem, data.get("description", "No description"))
            except Exception:
                tbl.add_row(p.stem, "[red]Error loading playbook[/red]")

        console.print(tbl)
        return

    if args[0] == "run":
        if len(args) < 2:
            console.print("  Usage: playbook run <name>", style="yellow")
            return

        if state.workspace is None:
            console.print("  [red]✗[/red] No active workspace.")
            return

        if state.active_credential_id is None:
            console.print("  [red]✗[/red] No active credential. Use 'use <id>' first.")
            return

        name = args[1]
        path = playbook_dir / f"{name}.yaml"
        if not path.exists():
            console.print(f"  [red]✗[/red] Playbook '{name}' not found.")
            return

        import threading
        import time as _time

        from rich.live import Live
        from rich.spinner import Spinner
        from rich.text import Text as _Text

        from quantum_mechanic.core.telemetry import TelemetryLevel, TelemetryType

        start_ts = _time.monotonic()
        _results: list = []
        _exc: list = [None]
        event_queue: queue.Queue = queue.Queue()

        # Build runner with telemetry callback
        tech_runner = state.runner
        if not tech_runner:
            console.print("  [red]✗[/red] Could not initialize technique runner.")
            return

        pb_runner = PlaybookRunner(tech_runner, on_event=lambda e: event_queue.put(e))

        def _worker() -> None:
            try:
                _results.extend(pb_runner.run_file(path))
            except Exception as e:
                _exc[0] = e

        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()

        console.print(f"  [bold blue]▶[/bold blue] Running playbook: [bold]{name}[/bold]")

        with Live("", refresh_per_second=8, transient=True) as live:
            while worker.is_alive() or not event_queue.empty():
                # 1. Drain the event queue
                while not event_queue.empty():
                    try:
                        event = event_queue.get_nowait()
                        if event.event_type == TelemetryType.LOG:
                            color = "white"
                            if event.level == TelemetryLevel.SUCCESS:
                                color = "green"
                            elif event.level == TelemetryLevel.WARNING:
                                color = "yellow"
                            elif event.level == TelemetryLevel.ERROR:
                                color = "red"

                            prefix = "    "
                            # If the message looks like a technique starting, add extra spacing
                            if "Starting technique" in (event.message or ""):
                                live.console.print(
                                    f"\n  [bold white]─[/bold white] [cyan]{event.message}[/cyan]"
                                )
                            else:
                                live.console.print(f"{prefix}[{color}]{event.message}[/{color}]")
                        elif event.event_type == TelemetryType.DISCOVERY:
                            live.console.print(
                                f"    [bold green]✓[/bold green] Discovered: [dim]{event.message}[/dim]"
                            )
                        elif event.event_type == TelemetryType.FINDING:
                            live.console.print(
                                f"    [bold red]![/bold red] Finding: [bold]{event.message}[/bold]"
                            )
                    except queue.Empty:
                        break

                # 2. Update the spinner
                elapsed = _time.monotonic() - start_ts
                txt = _Text()
                txt.append("  ")
                txt.append(f"playbook: {name}", style="bold blue")
                txt.append(f"  {elapsed:.1f}s elapsed", style="dim")
                live.update(Spinner("dots", text=txt))
                _time.sleep(0.05)

        worker.join()
        if _exc[0] is not None:
            raise _exc[0]

        console.print(
            f"  [bold green]✓[/bold green] Playbook '[bold]{name}[/bold]' finished. {len(_results)} techniques executed."
        )
        return

    console.print("  Usage: playbook [list|run <name>]", style="yellow")


def cmd_acquire(state: ShellState, args: list[str]) -> None:
    """Acquire tokens interactively: acquire <provider> <method> [options]."""
    # Subcommand validation — print suggestion if unknown
    err = _check_subcommand("acquire", args)
    if err:
        console.print(err)
        return

    if not args:
        console.print("  Usage: acquire <provider> <method> [options]", style="yellow")
        console.print(
            "    acquire entra device_code [--tenant <tid>] [--client <id>] [--resource <url>]"
        )
        console.print(
            "    acquire entra interactive [--tenant <tid>] [--client <id>] [--resource <url>]"
        )
        console.print("    acquire entra ropc --username <upn> --password <pw> [--tenant <tid>]")
        console.print("    acquire entra refresh [--tenant <tid>] [--resource <url>]")
        console.print(
            "    acquire entra arm                                  Pivot to Azure ARM via FOCI"
        )
        return

    provider = args[0].lower()
    if provider == "entra":
        acquire_entra(state, args[1:])
    else:
        console.print(f"  [red]✗[/red] Unsupported provider: {provider}. Use: entra")


def cmd_export(state: ShellState, args: list[str]) -> None:
    """Export token material: export <provider> <format> [options]."""
    # Subcommand validation — print suggestion if unknown
    err = _check_subcommand("export", args)
    if err:
        console.print(err)
        return

    if not args:
        console.print("  Usage: export <provider> <format> [options]", style="yellow")
        console.print("    export entra roadtools [--out /path/to/.roadtools_auth]")
        console.print("    export entra token [--type access_token|refresh_token]")
        console.print("    export entra describe")
        return

    provider = args[0].lower()
    if provider == "entra":
        export_entra(state, args[1:])
    else:
        console.print(f"  [red]✗[/red] Unsupported provider: {provider}. Use: entra")


def _capture_azure_token() -> dict[str, Any]:
    """Capture an Azure access token from local DefaultAzureCredential state.

    Returns a secret_data dict with method=captured_token. Raises on failure.

    This is the ONLY place in production code that constructs
    DefaultAzureCredential. It runs at import time, by explicit operator
    consent, captured once. The result is persisted to the workspace as
    a static token — at use time, the provider returns ONLY that stored
    token, never re-resolving against local state.
    """
    import base64
    import json as _json

    from azure.identity import DefaultAzureCredential

    live = DefaultAzureCredential()
    token = live.get_token("https://management.azure.com/.default")

    parts = token.token.split(".")
    if len(parts) < 2:
        raise RuntimeError("Could not parse captured token as JWT")
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    claims = _json.loads(base64.urlsafe_b64decode(payload))
    captured_upn = claims.get("upn") or claims.get("appid") or claims.get("sub", "unknown")

    return {
        "method": "captured_token",
        "access_token": token.token,
        "expires_on": token.expires_on,
        "captured_principal": captured_upn,
        "captured_tenant": claims.get("tid", "unknown"),
    }


def _capture_gcp_token() -> dict[str, Any]:
    """Capture a GCP access token from local ADC state.

    Returns a secret_data dict with method=captured_token. Raises on failure.

    This is the ONLY place in production code that constructs
    google.auth.default(). It runs at import time, by explicit operator
    consent, captured once. The result is persisted to the workspace as
    a static token — at use time, the provider returns ONLY that stored
    token, never re-resolving against local ADC state.
    """
    import google.auth
    from google.auth.transport.requests import Request

    live, project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    live.refresh(Request())
    captured_principal = (
        getattr(live, "service_account_email", None) or getattr(live, "_account", None) or "unknown"
    )
    return {
        "method": "captured_token",
        "access_token": live.token,
        "captured_principal": captured_principal,
        "project_id": project or "",
        # The real token expiry, captured at import time — GCPAuthProvider
        # uses this instead of fabricating an arbitrary one, so the stored
        # credential's freshness actually reflects the live token's lifetime.
        "expiry": live.expiry.isoformat() if live.expiry else None,
    }


# ================================================================
# Command registry — baseline commands. Additional environment-
# specific commands may be injected by app.py at startup.
# ================================================================
COMMANDS: dict[str, Any] = {
    "workspace": cmd_workspace,
    "import": cmd_import,
    "creds": cmd_creds,
    "use": cmd_use,
    "run": cmd_run,
    "playbook": cmd_playbook,
    "reload": cmd_reload,
    "techniques": cmd_techniques,
    "loot": cmd_loot,
    "report": cmd_report,
    "activity": cmd_activity,
    "raw": cmd_raw,
    "ask": cmd_ask,
    "check-ca-bypasses": cmd_check_ca_bypasses,
    "acquire": cmd_acquire,
    "export": cmd_export,
    "help": cmd_help,
    "info": cmd_help,  # alias: `info escalation/assume_role_chain`
}


# ================================================================
# Structured help registry
# ================================================================
#
# Source of truth for both `help <command>` in-shell output and the
# auto-generated docs/wiki/Commands.md page. Adding a new command
# without a CommandHelp record fails the
# test_every_shell_command_has_help_record test.
# ================================================================
COMMAND_HELP: dict[str, CommandHelp] = {
    # --- workspaces ---
    "workspace": CommandHelp(
        name="workspace",
        category="workspaces",
        synopsis="Create, load, list, or delete engagement workspaces",
        description=(
            "An engagement workspace is a SQLite database that stores "
            "credentials, discovered resources, evidence, and findings. "
            "Each engagement lives in its own workspace."
        ),
        subcommands=[
            SubcommandHelp(
                name="create",
                synopsis="Create a new workspace",
                args="<name>",
                example="workspace create acme-q4",
            ),
            SubcommandHelp(
                name="load",
                synopsis="Open an existing workspace",
                args="<name>",
                example="workspace load acme-q4",
            ),
            SubcommandHelp(name="list", synopsis="List all workspaces"),
            SubcommandHelp(name="delete", synopsis="Delete a workspace", args="<name>"),
        ],
        examples=[
            "workspace create test",
            "workspace load test",
        ],
    ),
    # --- credentials ---
    "import": CommandHelp(
        name="import",
        category="credentials",
        synopsis="Import a credential into the active workspace",
        description=(
            "Imports cloud credentials. For Azure/GCP --default flows, captures "
            "the access token at import time (the credential is then isolated "
            "from later CLI session changes — see docs/architecture/spec.md §5.3)."
        ),
        subcommands=[
            SubcommandHelp(
                name="aws",
                synopsis="Import AWS credential",
                args="--profile <name> | --access-key <key> --secret-key <s>",
            ),
            SubcommandHelp(
                name="azure",
                synopsis="Import Azure credential",
                args="--default | --client-id <id> --client-secret <s> --tenant-id <t>",
            ),
            SubcommandHelp(
                name="gcp",
                synopsis="Import GCP credential",
                args="--default | --key-file <path>",
            ),
            SubcommandHelp(name="oci", synopsis="Import OCI credential", args="--default"),
            SubcommandHelp(
                name="entra",
                synopsis="Import Entra ID tokens",
                args="browserdump <path> | roadtools <path> | refresh_token <tok> [--client <id>]",
            ),
        ],
        flags=[
            FlagHelp(
                name="--client",
                value="<id>",
                synopsis=(
                    "(entra refresh_token/prt_cookie/ests_cookie) Client GUID, or a "
                    "short alias: office | vs-legacy | az-cli | az-ps | graph-cli"
                ),
            ),
        ],
        examples=[
            "import aws --profile default",
            "import azure --default",
            "import gcp --default --project my-project",
        ],
    ),
    "creds": CommandHelp(
        name="creds",
        category="credentials",
        synopsis="List or manage workspace credentials",
        description=(
            "Shows imported credentials, renders per-credential detail with "
            "`creds <id>`, and lets you delete them by ID."
        ),
        subcommands=[
            SubcommandHelp(
                name="delete",
                synopsis="Remove a credential by ID",
                args="<id>",
                example="creds delete 2",
            ),
        ],
        flags=[
            FlagHelp(name="--provider", value="<name>", synopsis="Filter by provider"),
            FlagHelp(name="--active", synopsis="Show only active credentials"),
        ],
        examples=["creds", "creds 2", "creds --provider aws", "creds delete 2"],
    ),
    "use": CommandHelp(
        name="use",
        category="credentials",
        synopsis="Activate a credential for subsequent commands",
        description="Sets the active credential by ID. Pass `none` to clear.",
        examples=["use 1", "use none"],
    ),
    "raw": CommandHelp(
        name="raw",
        category="credentials",
        synopsis="Show raw JSON for a credential or principal",
        description="Reveals the underlying credential record stored in the workspace.",
        examples=["raw 1"],
    ),
    "acquire": CommandHelp(
        name="acquire",
        category="credentials",
        synopsis="Acquire a new Entra credential interactively",
        description=(
            "Drives device-code or browser flows to obtain Entra tokens. "
            "--client accepts a short alias instead of a raw client GUID."
        ),
        subcommands=[
            SubcommandHelp(
                name="entra device_code",
                synopsis="Interactive device-code login",
                args="[--client <id>] [--resource <url>] [--tenant <id>]",
                example="acquire entra device_code --client graph-cli",
            ),
            SubcommandHelp(
                name="entra interactive",
                synopsis="Browser-based OAuth login (auth code + PKCE)",
                args="[--tenant <id>] [--client <id>] [--resource <url>] [--timeout <secs>]",
                example="acquire entra interactive --tenant contoso.onmicrosoft.com",
            ),
            SubcommandHelp(
                name="entra arm",
                synopsis="Pivot Entra credential into Azure ARM (FOCI)",
            ),
        ],
        flags=[
            FlagHelp(
                name="--client",
                value="<id>",
                synopsis=(
                    "Client GUID, or a short alias: office | vs-legacy | az-cli | az-ps | graph-cli"
                ),
            ),
        ],
    ),
    "export": CommandHelp(
        name="export",
        category="credentials",
        synopsis="Export credential material for offline use",
        description="Prints raw tokens or decoded JWT claims for an imported Entra credential.",
        subcommands=[
            SubcommandHelp(
                name="entra token",
                synopsis="Print raw access token",
                args="[--resource <res>]",
                example="export entra token --resource https://graph.microsoft.com",
            ),
            SubcommandHelp(name="entra describe", synopsis="Decode and display JWT claims"),
        ],
        examples=[
            "export entra token --resource https://graph.microsoft.com > token.txt",
            'azurehound list -j "$(cat token.txt)" -t <tenant-id> az-ad -o azurehound-ad.json',
        ],
    ),
    # --- techniques ---
    "techniques": CommandHelp(
        name="techniques",
        category="techniques",
        synopsis="List discovery, escalation, lateral, and exfil techniques",
        description=(
            "Lists techniques available for the active credential's provider. "
            "Supports filtering by tactic / provider / safe flag, and positional "
            "substring search against id and description."
        ),
        flags=[
            FlagHelp(name="--all", synopsis="Show all techniques regardless of active provider"),
            FlagHelp(
                name="--tactic",
                value="<name>",
                synopsis="Filter by ATT&CK tactic (discovery, escalation, etc.)",
            ),
            FlagHelp(
                name="--provider",
                value="<name>",
                synopsis="Filter by provider (aws, azure, gcp, oci, entra)",
            ),
            FlagHelp(name="--safe", synopsis="Only safe (read-only) techniques"),
            FlagHelp(name="--unsafe", synopsis="Only state-changing techniques"),
        ],
        examples=[
            "techniques",
            "techniques --tactic discovery",
            "techniques --provider azure --safe",
            "techniques whoami     # positional substring search",
        ],
    ),
    "run": CommandHelp(
        name="run",
        category="techniques",
        synopsis="Execute a technique by ID",
        description="Runs the named technique against the active credential.",
        flags=[
            FlagHelp(
                name="--safe",
                synopsis="Validate without state changes (where supported)",
            ),
            FlagHelp(
                name="--param",
                value="key=value",
                synopsis="Pass a parameter to the technique",
            ),
        ],
        examples=[
            "run discovery/whoami",
            "run discovery/enum_compute --param target=vm-name",
        ],
    ),
    "reload": CommandHelp(
        name="reload",
        category="techniques",
        synopsis="Hot-reload technique modules without restarting qm",
        description=(
            "Re-imports every technique module from disk so newly added or "
            "edited techniques become available in the current shell session."
        ),
        examples=["reload"],
    ),
    # --- playbooks ---
    "playbook": CommandHelp(
        name="playbook",
        category="playbooks",
        synopsis="Manage and run YAML playbooks",
        description=(
            "Playbooks are YAML files in src/quantum_mechanic/playbooks/ that "
            "chain techniques together. `playbook list` enumerates available "
            "playbooks; `playbook run <name>` executes one against the active "
            "credential."
        ),
        subcommands=[
            SubcommandHelp(name="list", synopsis="List available playbooks"),
            SubcommandHelp(
                name="run",
                synopsis="Run a playbook by name",
                args="<name>",
                example="playbook run aws_quick_recon",
            ),
        ],
        examples=["playbook list", "playbook run aws_quick_recon"],
    ),
    # --- evidence / reporting ---
    "loot": CommandHelp(
        name="loot",
        category="evidence",
        synopsis="Display saved loot from previous technique runs",
        description=(
            "Loot files are CSV/JSON artifacts dropped by techniques into the "
            "workspace's loot directory. With no args, lists all loot. Pass a "
            "technique ID to render just that technique's loot."
        ),
        examples=["loot", "loot discovery/whoami"],
    ),
    "activity": CommandHelp(
        name="activity",
        category="evidence",
        synopsis="View the workspace activity log",
        description=(
            "Shows the chronological log of technique runs, errors, and "
            "workspace mutations. Filter by technique ID, log level, or "
            "row count."
        ),
        flags=[
            FlagHelp(
                name="--level",
                value="<LEVEL>",
                synopsis="Filter by log level (INFO, WARNING, ERROR)",
            ),
            FlagHelp(
                name="--limit",
                value="<N>",
                synopsis="Limit the number of rows shown (default 50)",
            ),
        ],
        examples=[
            "activity",
            "activity discovery/whoami",
            "activity --level ERROR --limit 20",
        ],
    ),
    "report": CommandHelp(
        name="report",
        category="reporting",
        synopsis="Render an engagement narrative",
        description="Prints the credential chain, technique timeline, and findings inline.",
    ),
    # --- advanced ---
    "ask": CommandHelp(
        name="ask",
        category="advanced",
        synopsis="Ask the Quantum Mechanic RAG agent for advice",
        description=(
            "Sends a natural-language question to the RAG agent, which reasons "
            "over the current workspace's evidence and findings. Requires the "
            "optional `[agent]` install extra."
        ),
        examples=[
            "ask what should I run next?",
            "ask any privesc paths from my current creds?",
        ],
    ),
    "check-ca-bypasses": CommandHelp(
        name="check-ca-bypasses",
        category="advanced",
        synopsis="Analyze Entra Conditional Access policies for bypass opportunities",
        description=(
            "Reads stored Conditional Access policy evidence (from "
            "discovery/entra_enum_conditional_access_policies) and highlights "
            "policies that can be bypassed via excluded users/apps, named "
            "locations, or device-state assumptions."
        ),
        examples=["check-ca-bypasses"],
    ),
    # --- shell / meta ---
    "help": CommandHelp(
        name="help",
        category="shell",
        synopsis="Show command help or technique documentation",
        description=(
            "With no args, lists all commands. With a name, shows that command's full help."
        ),
        examples=["help", "help creds", "help discovery/whoami"],
    ),
    "info": CommandHelp(
        name="info",
        category="shell",
        synopsis="Alias for `help` — show command or technique documentation",
        description=(
            "Same as `help`. Convenient when the operator thinks 'info "
            "<technique>' instead of 'help <technique>'."
        ),
        examples=["info escalation/assume_role_chain"],
    ),
}


def _parse_opts(args: list[str]) -> dict[str, str]:
    """Parse --key value pairs into a dict.

    Also handles bare flags like --default (value set to 'true').
    """
    opts: dict[str, str] = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            key = args[i][2:]
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                opts[key] = args[i + 1]
                i += 2
            else:
                opts[key] = "true"
                i += 1
        else:
            i += 1
    return opts
