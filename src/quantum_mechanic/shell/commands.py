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
from typing import Any

from rich.console import Console

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueRunner
from quantum_mechanic.core.transport import LocalTransport, Transport
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell import formatters

console = Console()


class ShellState:
    """Mutable state for the interactive shell session."""

    def __init__(
        self,
        workspace: Workspace | None = None,
        loader: TechniqueLoader | None = None,
        registry: ProviderRegistry | None = None,
        transport: Transport | None = None,
    ) -> None:
        self.workspace = workspace
        self.loader = loader or TechniqueLoader()
        self.registry = registry or ProviderRegistry()
        self._transport = transport  # explicit transport override (e.g. RemoteTransport)
        self.active_credential_id: int | None = None
        self.active_credential_label: str | None = None

    @property
    def transport(self) -> Transport | None:
        """The active transport. LocalTransport when a workspace is loaded.

        Returns None if no workspace is active — callers must guard.
        An explicit transport passed to __init__ takes precedence, enabling
        daemon/remote mode by passing RemoteTransport here.
        """
        if self._transport is not None:
            return self._transport
        if self.workspace is not None:
            return LocalTransport(self.workspace, self.loader, self.registry)
        return None

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
            state.workspace = Workspace.create(name)
            state._runner = None
            console.print(f"  [green]✓[/green] Created workspace: [bold]{name}[/bold]")
        except FileExistsError:
            console.print(f"  [red]✗[/red] Workspace '{name}' already exists", style="red")

    elif subcmd == "load":
        if len(args) < 2:
            console.print("  Usage: workspace load <name>", style="yellow")
            return
        name = args[1]
        try:
            state.workspace = Workspace.load(name)
            state._runner = None
            console.print(f"  [green]✓[/green] Loaded workspace: [bold]{name}[/bold]")
        except FileNotFoundError:
            console.print(f"  [red]✗[/red] Workspace '{name}' not found", style="red")

    elif subcmd == "list":
        workspaces = Workspace.list_all()
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
    else:
        console.print(f"  [red]✗[/red] Unsupported provider: {provider}. Use: aws, azure, gcp, oci")


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

    _validate_and_import(state, "gcp", cred_type, secret, friendly)


def _import_oci(state: ShellState, opts: dict[str, str]) -> None:
    """Import OCI credentials."""
    profile = opts.get("profile", "DEFAULT")
    config_file = opts.get("config-file")

    secret: dict[str, str] = {"method": "config_file", "profile": profile}
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
    formatters.format_credentials(creds)


def cmd_use(state: ShellState, args: list[str]) -> None:
    """Set the active credential: use <id>."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace/connection.")
        return

    if not args:
        console.print("  Usage: use <credential_id>", style="yellow")
        return

    try:
        cred_id = int(args[0])
        creds = state.transport.list_credentials()
        cred = next((c for c in creds if c.get("id") == cred_id), None)
        if cred:
            state.active_credential_id = cred_id
            if state.workspace:
                state.workspace.active_credential_id = cred_id

            provider = cred.get('provider', 'unknown')
            identity = cred.get("friendly_name") or cred.get("credential_type", "unknown")
            state.active_credential_label = f"{provider}:{identity}"

            console.print(
                f"  [green]✓[/green] Active: {provider.upper()} {identity} (#{cred_id})"
            )
        else:
            console.print(f"  [red]✗[/red] Credential #{cred_id} not found")
    except ValueError:
        console.print(f"  [red]✗[/red] Invalid credential ID: {args[0]}")


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
    # Parse --param key=value flags from remaining args.
    # E.g. run lateral_movement/azure_run_command --param vm_id=/subscriptions/.../vm
    # --------------------------------------------------------
    params: dict[str, str] = {}
    i = 1
    while i < len(args):
        if args[i] == "--param" and i + 1 < len(args):
            kv = args[i + 1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k.strip()] = v.strip()
            i += 2
        else:
            i += 1

    result = state.transport.run_technique(
        technique_id,
        params=params if params else None,
        credential_id=state.active_credential_id
    )
    formatters.format_technique_result(result)


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
        # Go through transport — works in both local and remote mode.
        techniques = list(state.transport.list_techniques(provider=active_provider))
        # list_techniques returns TechniqueMetadata; formatters expect RegisteredTechnique.
        # Build minimal RegisteredTechnique wrappers to stay compatible.
        from quantum_mechanic.core.loader import RegisteredTechnique
        wrapped = [
            RegisteredTechnique(metadata=m, function=lambda _: None, module_path="")
            for m in techniques
        ]
        if active_provider:
            console.print(
                f"  [dim]Filtering techniques for active provider: "
                f"[bold]{active_provider}[/bold][/dim]"
            )
        formatters.format_techniques_list(wrapped)
    else:
        # No workspace / transport — show all loaded techniques.
        techniques_all = state.loader.list_all()
        formatters.format_techniques_list(techniques_all)


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
        safe_label = "[green]Yes — read-only[/green]" if m.safe else "[red]No — modifies state[/red]"
        console.print(f"\n[bold cyan]ID:[/bold cyan]        {m.id}")
        console.print(f"[bold cyan]Tactic:[/bold cyan]    {m.tactic}")
        console.print(f"[bold cyan]MITRE:[/bold cyan]     {m.mitre_id or '—'}")
        console.print(f"[bold cyan]Providers:[/bold cyan] {', '.join(m.providers)}")
        console.print(f"[bold cyan]Severity:[/bold cyan]  {m.severity}")
        console.print(f"[bold cyan]Safe:[/bold cyan]      {safe_label}")
        if m.safe_mode_available:
            console.print("[bold cyan]Safe Mode:[/bold cyan] Supported (--safe flag)")
        console.print(f"\n[bold]Description:[/bold]\n  {m.description}\n")

        # Pull PARAMETERS and USAGE from the module source block comments
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
            if params_lines:
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
    "reload": cmd_reload,
    "techniques": cmd_techniques,
    "report": cmd_report,
    "raw": cmd_raw,
    "ask": cmd_ask,
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
