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

import json
import queue
from pathlib import Path
from typing import Any

from rich.console import Console

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.playbook import PlaybookRunner
from quantum_mechanic.core.runner import TechniqueRunner
from quantum_mechanic.core.transport import LocalTransport, Transport
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell import formatters
from quantum_mechanic.shell.commands_entra import acquire_entra, export_entra, import_entra

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

    def set_workspace(self, workspace: Workspace) -> None:
        """Update the active workspace and re-initialise the local transport."""
        self.workspace = workspace
        self._transport = LocalTransport(self.workspace, self.loader, self.registry)
        self.active_credential_id = None
        self.active_credential_label = None
        self._extra_providers = []

        # Re-register callback if one was active
        if self._agent_update_callback:
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
            op   = getattr(self._transport, "operator", None)
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

    else:
        console.print(f"  Unknown subcommand: {subcmd}. Use: create, load, list", style="yellow")


def cmd_import(state: ShellState, args: list[str]) -> None:
    """Import credentials: import <provider> [options]."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace/connection. Run 'workspace create <name>' first.")
        return

    if not args:
        console.print("  Usage: import <provider> [options]", style="yellow")
        console.print("    import aws --profile <name>")
        console.print("    import aws --access-key <key> --secret-key <secret>")
        console.print("    import azure --default")
        console.print(
            "    import azure --client-id <id> --client-secret <secret> --tenant-id <tid>"
        )
        console.print("    import gcp --default")
        console.print("    import gcp --key-file /path/to/sa.json")
        console.print("    import oci --default")
        console.print("    import oci --profile <profile_name>")
        console.print("    import oci --user <id> --tenancy <id> --fingerprint <hash> --key-file <path> --region <reg>")
        console.print("    import entra browserdump /path/to/dump.json")
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
        console.print(f"  [red]✗[/red] Unsupported provider: {provider}. Use: aws, azure, gcp, oci, entra")


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
        provider_impl.authenticate(secret)
    except Exception as e:
        friendly_msg = _friendly_error(e, provider)
        console.print(f"  [red]✗[/red] {friendly_msg}")
        return

    # --------------------------------------------------------
    # Credentials are valid — store them.
    # --------------------------------------------------------
    cred_id = state.transport.add_credential(  # type: ignore[union-attr]
        provider=provider,
        credential_type=credential_type,
        secret_data=json.dumps(secret),
        friendly_name=friendly,
    )
    console.print(
        f"  [green]✓[/green] Imported {provider.upper()} credential #{cred_id}: {friendly}"
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
    """Import Azure credentials."""
    if "default" in opts or not opts:
        secret: dict = {"method": "default"}
        friendly = "DefaultAzureCredential"
        cred_type = "access_key"
    elif "client-id" in opts:
        if "client-secret" not in opts or "tenant-id" not in opts:
            console.print(
                "  [red]✗[/red] SP auth requires --client-id, --client-secret, and --tenant-id"
            )
            return
        secret = {
            "tenant_id": opts["tenant-id"],
            "client_id": opts["client-id"],
            "client_secret": opts["client-secret"],
        }
        friendly = f"SP:{opts['client-id'][:8]}..."
        cred_type = "service_principal"
    else:
        secret = {"method": "default"}
        friendly = "DefaultAzureCredential"
        cred_type = "access_key"

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
        secret = {"method": "default"}
        friendly = "ApplicationDefaultCredentials"
        cred_type = "service_account"

    if "project" in opts:
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
            "region": opts["region"]
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


def cmd_creds(state: ShellState, args: list[str]) -> None:
    """List or delete credentials: creds, creds delete <id>."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace.")
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
        from quantum_mechanic.shell.commands_entra import _entra_friendly_name
        from quantum_mechanic.providers.entra.token_store import EntraTokenStore as _ETS
        for cred in creds:
            if cred.get("provider") == "entra" and cred.get("credential_type") == "token_store":
                try:
                    raw = state.workspace.get_credential_secret(cred["id"])
                    if not raw:
                        continue
                    data = _json.loads(raw)
                    store = _ETS.from_dict(data.get("token_store", data))
                    cred["_token_summary"] = store.token_summary()
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
        from datetime import datetime as _dt, timezone as _tz

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
                        exp_dt = exp_dt.replace(tzinfo=_tz.utc)
                    if _dt.now(_tz.utc) >= exp_dt:
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
        creds = state.transport.list_credentials()
        cred = next((c for c in creds if c.get("id") == cred_id), None)
        if cred:
            state.active_credential_id = cred_id
            state._extra_providers = []
            if state.workspace:
                state.workspace.active_credential_id = cred_id

            provider = cred.get('provider', 'unknown')
            identity = cred.get("friendly_name") or cred.get("credential_type", "unknown")
            # Use friendly_name directly — it already encodes the provider context.
            state.active_credential_label = identity

            console.print(
                f"  [green]✓[/green] Active: {provider.upper()} {identity} (#{cred_id})"
            )

            if provider == "entra":
                _try_restore_arm_pivot(state)
        else:
            console.print(f"  [red]✗[/red] Credential #{cred_id} not found")
    except ValueError:
        console.print(f"  [red]✗[/red] Invalid credential ID: {args[0]}")


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
        "value_col": "instance_id",   # GCP uses VM name; OCI requires manual OCID
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
            count = sum(1 for line in f.read_text().splitlines() if line.strip() and not line.startswith("#"))
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
    state: "ShellState",
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
        console.print(f"  [dim]No loot for {loot_technique} — run it first to populate targets.[/dim]")
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
                    console.print(f"  [yellow]⚠ VM state is '{pwr}' — command will likely fail.[/yellow]")
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


def cmd_run(state: ShellState, args: list[str]) -> None:
    """Run a technique: run <technique_id> [--param key=value ...]"""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace.")
        return

    if not args:
        console.print("  Usage: run <technique_id> [--param key=value]", style="yellow")
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
    i = 1
    while i < len(args):
        arg = args[i]
        if arg == "--param" and i + 1 < len(args):
            kv = args[i + 1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip()] = v.strip()
            i += 2
        elif arg == "--note" and i + 1 < len(args):
            note = args[i + 1]
            i += 2
        elif "=" in arg and not arg.startswith("-"):
            k, v = arg.split("=", 1)
            params[k.strip()] = v.strip()
            i += 1
        else:
            i += 1

    if note:
        params["_run_note"] = note

    # ── Parameter hint / interactive picker for missing required params ─────
    if state.loader:
        registered = state.loader.get(technique_id)
        if registered and registered.metadata.parameters:
            missing = [
                p for p in registered.metadata.parameters
                if p.required and p.name not in params
            ]
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
                parts = " ".join(
                    f"{p.name}={p.example or '<value>'}" for p in missing
                )
                console.print(f"  [dim]Usage: run {technique_id} {parts}[/dim]")
                return

    # ── Auto-pivot entra → azure when technique requires it ─────────────────
    # If the active credential is entra and the technique supports azure (but
    # not entra), try to restore the ARM pivot before running so the user
    # doesn't need to manually `acquire entra arm` on every session start.
    if state.loader and state.active_credential_id is not None:
        _active_creds = state.transport.list_credentials() if state.transport else []
        _cred_info = next((c for c in _active_creds if c.get("id") == state.active_credential_id), None)
        if _cred_info and _cred_info.get("provider") == "entra":
            _registered = state.loader.get(technique_id)
            if _registered:
                _allowed = set(_registered.metadata.providers)
                if "azure" in _allowed and "entra" not in _allowed and "azure" not in state._extra_providers:
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
                        if event.level == TelemetryLevel.SUCCESS: color = "green"
                        elif event.level == TelemetryLevel.WARNING: color = "yellow"
                        elif event.level == TelemetryLevel.ERROR: color = "red"

                        prefix = "    "
                        live.console.print(f"{prefix}[{color}]{event.message}[/{color}]")
                    elif event.event_type == TelemetryType.DISCOVERY:
                        live.console.print(f"    [bold green]✓[/bold green] Discovered: [dim]{event.message}[/dim]")
                    elif event.event_type == TelemetryType.FINDING:
                        live.console.print(f"    [bold red]![/bold red] Finding: [bold]{event.message}[/bold]")
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

    formatters.format_technique_result(_result[0])



def cmd_techniques(state: ShellState, args: list[str]) -> None:
    """List available techniques, filtered by the active credential's provider."""
    # --------------------------------------------------------
    # Determine active provider for filtered listing.
    # --------------------------------------------------------
    active_provider = None
    if state.transport and state.active_credential_id:
        creds = state.transport.list_credentials()
        cred = next((c for c in creds if c.get("id") == state.active_credential_id), None)
        if cred:
            active_provider = cred.get("provider")

    if state.transport is not None:
        from quantum_mechanic.core.loader import RegisteredTechnique

        extra = state._extra_providers
        if extra:
            # Multiple providers unlocked — fetch all and filter client-side.
            all_providers = ({active_provider} if active_provider else set()) | set(extra)
            all_techniques = list(state.transport.list_techniques(provider=None))
            techniques = [
                m for m in all_techniques
                if any(p in all_providers for p in m.providers)
            ]
            label = ", ".join(sorted(all_providers))
            console.print(
                f"  [dim]Filtering techniques for active providers: [bold]{label}[/bold][/dim]"
            )
        else:
            techniques = list(state.transport.list_techniques(provider=active_provider))
            if active_provider:
                console.print(
                    f"  [dim]Filtering techniques for active provider: "
                    f"[bold]{active_provider}[/bold][/dim]"
                )

        # list_techniques returns TechniqueMetadata; formatters expect RegisteredTechnique.
        wrapped = [
            RegisteredTechnique(metadata=m, function=lambda _: None, module_path="")
            for m in techniques
        ]
        formatters.format_techniques_list(wrapped)
    else:
        # No workspace / transport — show all loaded techniques.
        techniques_all = state.loader.list_all()
        formatters.format_techniques_list(techniques_all)


def cmd_loot(state: ShellState, args: list[str]) -> None:
    """Display saved loot from previous technique runs: loot [technique_id]"""
    import csv
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
        _render_loot_dir(loot_dir, target_id)
        return

    # Otherwise list all available loot dirs
    csv_files = sorted(loot_root.rglob("loot.csv"))
    if not csv_files:
        console.print("  [dim]No loot.csv files found.[/dim]")
        return

    for csv_path in csv_files:
        rel = csv_path.parent.relative_to(loot_root)
        tech_id = str(rel)
        _render_loot_dir(csv_path.parent, tech_id)
        console.print()


def _render_loot_dir(loot_dir, tech_id: str) -> None:
    """Render a single loot directory inline."""
    import csv
    import importlib
    from pathlib import Path

    from rich import box
    from rich.table import Table

    csv_path = Path(loot_dir) / "loot.csv"
    if not csv_path.exists():
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
    # This picks up new columns added since the CSV was last written.
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

    # Deduplicate by primary key (first column), keeping the last written row.
    # This ensures re-runs show fresh data (e.g. IPs populated after fix)
    # rather than accumulating stale rows from earlier runs.
    if fieldnames:
        key_col = fieldnames[0]
        keyed: dict = {}
        for row in rows:
            keyed[row.get(key_col, "")] = row  # last write wins
        rows = list(keyed.values())
    else:
        seen: set = set()
        rows = [r for r in rows if (t := tuple(r.values())) not in seen and not seen.add(t)]

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

    # Import locally to avoid slow CLI startup if agent isn't used
    # And gracefully degrade if LangChain/Anthropic are not installed!
    try:
        from rich.markdown import Markdown

        from quantum_mechanic.agent.orchestrator import AgentOrchestrator
    except ImportError:
        console.print("\n[red]✗ Agent Dependencies Missing[/red]")
        console.print("  The RAG Agent is an optional feature.")
        console.print("  To enable it, install the AI dependencies:")
        console.print("  [bold cyan]pip install quantum-mechanic[agent][/bold cyan]")
        return

    with console.status("[cyan]Agent reasoning...[/cyan]"):
        try:
            agent = AgentOrchestrator(state.workspace)
            response = agent.ask(question)
        except Exception as e:
            if "api key" in str(e).lower() or "anthropic" in str(e).lower():
                console.print("\n[red]✗ Anthropic API Key Missing[/red]")
                console.print("  Please set the [bold cyan]ANTHROPIC_API_KEY[/bold cyan] environment variable.")
                return
            console.print(f"\n[red]✗ Agent Error:[/red] {e}")
            return

    console.print("\n[bold cyan]🧠 Quantum Mechanic Agent[/bold cyan]")
    console.print(Markdown(response))
    console.print()


def cmd_help(state: ShellState, args: list[str]) -> None:
    """Show available commands or technique documentation."""
    import importlib
    import inspect

    if args:
        tech_id = args[0].strip("/")
        registered = state.loader.get(tech_id)

        if registered is None:
            console.print(
                f"  [red]✗[/red] Technique '{tech_id}' not found. "
                "Use 'techniques' to list available modules."
            )
            return

        m = registered.metadata
        safe_label = "[green]Safe (Read-Only)[/green]" if m.safe else "[red]Impact (Modifies State)[/red]"

        console.print(f"\n[bold white]MODULE: {m.id}[/bold white]")
        console.print(f"  [dim]{m.description}[/dim]\n")

        # Key Intel
        intel = [
            f"[bold cyan]Tactic:[/bold cyan]    {m.tactic}",
            f"[bold cyan]MITRE ID:[/bold cyan]  {m.mitre_id or '—'}",
            f"[bold cyan]Providers:[/bold cyan] {', '.join(m.providers)}",
            f"[bold cyan]Severity:[/bold cyan]  {m.severity.upper()}",
            f"[bold cyan]Risk Profile:[/bold cyan] {safe_label}"
        ]
        for line in intel:
            console.print(f"  {line}")

        console.print()

        # 1. Show structured options if defined
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

            # 1.1 Show Usage Examples
            console.print("  [bold white]Usage Examples:[/bold white]")
            console.print(f"    qm> run {m.id}")
            # Generate a dynamic example if parameters have examples defined
            example_parts = [f"{p.name}={p.example}" for p in m.parameters if p.example]
            if example_parts:
                console.print(f"    qm> run {m.id} {' '.join(example_parts)}")
            console.print()

        # 2. Fallback to legacy block extraction for USAGE/DETAILS
        try:
            mod = importlib.import_module(registered.module_path)
            src = inspect.getsource(mod)

            def _extract_block(src: str, start_marker: str) -> list[str]:
                idx = src.find(start_marker)
                if idx == -1:
                    return []
                end = src.find("\n#\n", idx)
                block = src[idx:end if end != -1 else idx + 800]
                lines = []
                for ln in block.splitlines():
                    stripped = ln.lstrip("# ").rstrip()
                    lines.append(stripped)
                return lines

            params_lines = _extract_block(src, "# PARAMETERS")
            if params_lines and not m.parameters:
                console.print("[bold]Parameters (via --param key=value):[/bold]")
                for ln in params_lines[1:]:  # skip "PARAMETERS (via ctx.params)" header
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
            pass  # Source extraction is best-effort

        return

    from quantum_mechanic.shell import formatters
    formatters.format_help_menu(COMMANDS)


def cmd_report(state: ShellState, args: list[str]) -> None:
    """Render the engagement narrative inline in the terminal using Rich tables."""
    import json

    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree

    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace/connection. Load one first.")
        return

    transport = state.transport
    info = transport.workspace_info()
    ws_name = info.get("name", "Unknown Workspace")

    # ── Header ──────────────────────────────────────────────────────
    from datetime import UTC, datetime
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    creds_all = transport.list_credentials()
    providers = ", ".join(sorted({c.get("provider", "unknown").upper() for c in creds_all})) or "none"
    console.print(Panel(
        f"[bold white]Attack Path — {ws_name}[/bold white]\n"
        f"[dim]Updated: {now_str}   Providers: {providers}[/dim]",
        style="blue",
    ))

    # ── Credential Chain ─────────────────────────────────────────────
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
                status_style = "red" if status == "expired" else (
                    "yellow" if status == "expiring" else "green"
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

    # ── Technique Timeline ───────────────────────────────────────────
    console.print("\n[bold cyan]Technique Timeline[/bold cyan]")
    evidence_rows = transport.list_evidence()
    if not evidence_rows:
        console.print("  [dim]No techniques have been run yet.[/dim]")
    else:
        tbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("Timestamp", width=16)
        tbl.add_column("Technique")
        tbl.add_column("Provider", width=8)
        tbl.add_column("Principal")

        for i, row in enumerate(evidence_rows, 1):
            ts = str(row.get("timestamp", ""))[:16]
            tech = row.get("technique_id", "unknown")
            provider = "?"
            principal = "?"
            try:
                data = json.loads(row.get("output_json", "{}"))
                provider = (data.get("provider") or "?").upper()
                principal = (
                    data.get("principal")
                    or data.get("friendly_name")
                    or data.get("starting_principal", "?").split("/")[-1]
                    or "?"
                )
            except Exception:
                pass
            tbl.add_row(str(i), ts, tech, provider, principal)

        console.print(tbl)

    # ── Findings ─────────────────────────────────────────────────────
    console.print("\n[bold cyan]Findings[/bold cyan]")
    findings = transport.list_findings()
    if not findings:
        console.print("  [dim]No findings recorded yet.[/dim]")
    else:
        _SEV_STYLE = {
            "critical": ("🔴", "bold red"),
            "high":     ("🟠", "bold yellow"),
            "medium":   ("🟡", "yellow"),
            "low":      ("🔵", "cyan"),
            "info":     ("⚪", "dim"),
        }
        ftbl = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
        ftbl.add_column("ID", width=5)
        ftbl.add_column("Severity", width=10)
        ftbl.add_column("Finding")
        ftbl.add_column("Provider", width=8)
        ftbl.add_column("Technique")

        for f in sorted(findings, key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                x.get("severity", "info").lower(), 99)
        )):
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
                            if event.level == TelemetryLevel.SUCCESS: color = "green"
                            elif event.level == TelemetryLevel.WARNING: color = "yellow"
                            elif event.level == TelemetryLevel.ERROR: color = "red"

                            prefix = "    "
                            # If the message looks like a technique starting, add extra spacing
                            if "Starting technique" in (event.message or ""):
                                live.console.print(f"\n  [bold white]─[/bold white] [cyan]{event.message}[/cyan]")
                            else:
                                live.console.print(f"{prefix}[{color}]{event.message}[/{color}]")
                        elif event.event_type == TelemetryType.DISCOVERY:
                            live.console.print(f"    [bold green]✓[/bold green] Discovered: [dim]{event.message}[/dim]")
                        elif event.event_type == TelemetryType.FINDING:
                            live.console.print(f"    [bold red]![/bold red] Finding: [bold]{event.message}[/bold]")
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

        console.print(f"  [bold green]✓[/bold green] Playbook '[bold]{name}[/bold]' finished. {len(_results)} techniques executed.")
        return

    console.print("  Usage: playbook [list|run <name>]", style="yellow")


def cmd_acquire(state: ShellState, args: list[str]) -> None:
    """Acquire tokens interactively: acquire <provider> <method> [options]."""
    if not args:
        console.print("  Usage: acquire <provider> <method> [options]", style="yellow")
        console.print("    acquire entra device_code [--tenant <tid>] [--client <id>] [--resource <url>]")
        console.print("    acquire entra ropc --username <upn> --password <pw> [--tenant <tid>]")
        console.print("    acquire entra refresh [--tenant <tid>] [--resource <url>]")
        console.print("    acquire entra arm                                  Pivot to Azure ARM via FOCI")
        return

    provider = args[0].lower()
    if provider == "entra":
        acquire_entra(state, args[1:])
    else:
        console.print(f"  [red]✗[/red] Unsupported provider: {provider}. Use: entra")


def cmd_export(state: ShellState, args: list[str]) -> None:
    """Export token material: export <provider> <format> [options]."""
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


# ================================================================
# Private commands (exploits, payloads, connect, disconnect, lois)
# are in shell/commands_private.py — NOT shipped in the public build.
# app.py loads them via try/except import if the file is present.
# ================================================================


# Command registry — public commands only.
# Private commands (exploits, payloads, connect, disconnect, lois)
# are injected by app.py at startup from commands_private.py.
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
    "raw": cmd_raw,
    "ask": cmd_ask,
    "acquire": cmd_acquire,
    "export": cmd_export,
    "help": cmd_help,
    "info": cmd_help,        # alias: `info escalation/assume_role_chain`
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
