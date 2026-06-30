# ================================================================
# MODULE: quantum_mechanic.shell.formatters
# ----------------------------------------------------------------
# PURPOSE:   Output formatting for human and agent modes.
#            Human mode uses rich tables. Agent mode outputs JSON.
#
# DESIGN:    All display logic goes through formatters so the
#            shell commands never directly print. This ensures
#            consistent output and easy testing.
# ================================================================

from __future__ import annotations

import json

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from quantum_mechanic.core.loader import RegisteredTechnique
from quantum_mechanic.core.runner import TechniqueResult

console = Console()


def format_banner() -> None:
    """Display the QM startup banner."""
    banner = Text()
    banner.append("  ██████  ███    ███\n", style="bold cyan")
    banner.append("  ██   ██ ████  ████\n", style="bold cyan")
    banner.append("  ██   ██ ██ ████ ██\n", style="bold cyan")
    banner.append("  ██▄▄▄██ ██  ██  ██\n", style="bold cyan")
    banner.append("  ███████ ██      ██\n", style="bold cyan")
    banner.append("\n  Quantum Mechanic v0.1.0", style="bold white")
    banner.append("\n  Cross-cloud offensive security framework\n", style="dim")
    console.print(Panel(banner, border_style="cyan", expand=False))


def format_credentials(creds: list[dict]) -> None:
    """Display credentials as a rich table."""
    if not creds:
        console.print("  No credentials loaded. Run 'import' to add one.", style="dim")
        return

    has_token_summary = any(c.get("_token_summary") for c in creds)

    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("#", style="bold cyan", width=4)
    table.add_column("Provider", style="bold")
    table.add_column("Type", style="dim")
    table.add_column("Identity", style="white")
    if has_token_summary:
        table.add_column("Tokens", style="dim cyan")
    table.add_column("Status", justify="center")

    for cred in creds:
        status = cred.get("status", "unknown")
        status_style = {
            "active": "bold green",
            "expiring": "bold yellow",
            "expired": "bold red",
            "revoked": "bold red",
        }.get(status, "dim")

        identity = cred.get("friendly_name") or cred.get("principal_id") or "unknown"
        row = [
            str(cred.get("id", "?")),
            cred.get("provider", "unknown").upper(),
            cred.get("credential_type", "unknown"),
            identity,
        ]
        if has_token_summary:
            row.append(cred.get("_token_summary", ""))
        row.append(Text(status, style=status_style))
        table.add_row(*row)

    console.print(table)


def format_declarative_result(result: TechniqueResult) -> None:
    """Generic renderer for techniques using LOOT_SCHEMA."""
    if not result.loot_schema:
        return

    data = result.data
    if data is None:
        return

    # 1. Resolve the list of items to render
    items: list[dict] = []
    if result.loot_items_key:
        if isinstance(data, dict):
            items = data.get(result.loot_items_key, [])
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]

    # Show count summary like legacy formatters did
    provider_str = result.provider.upper() if result.provider else "UNKNOWN"
    console.print(f"  [bold green]✓[/bold green] {len(items)} item(s) found — [dim]{provider_str}[/dim]")

    if not items:
        return

    # 2. Build the Rich table
    table = Table(box=box.ROUNDED, border_style="dim")

    for _, display_name, style in result.loot_schema:
        table.add_column(display_name or "Property", style=style or "white")

    for item in items:
        row_values = []
        for key, _, _ in result.loot_schema:
            val = item.get(key, "—")
            if val is None:
                val = "—"
            row_values.append(str(val))
        table.add_row(*row_values)

    console.print(table)


def format_technique_result(result: TechniqueResult) -> None:
    """Display a technique result.

    Priority:
      1. result.formatter_func (Decentralized pattern)
      2. result.loot_schema (Declarative pattern)
      3. Hardcoded logic below (Legacy pattern)
    """
    if result.status == "error":
        console.print(f"  [bold red]✗[/bold red] {result.error}")
        return

    processed = False

    # 1. Decentralized formatter (Manual override)
    if result.formatter_func:
        try:
            result.formatter_func(result)
            processed = True
        except Exception as e:
            from logging import getLogger
            logging_logger = getLogger("qm.shell")
            logging_logger.debug("Decentralized formatter failed for %s: %s", result.technique_id, e)
            processed = False

    # 2. Declarative formatter (The "Intelligent" path)
    if not processed and result.loot_schema:
        format_declarative_result(result)
        processed = True

    # 3. Legacy fallbacks
    if not processed:
        _legacy_format_result(result)

    # Timing line — only show API call count if > 0 (direct SDK calls aren't tracked)
    if result.api_calls > 0:
        console.print(f"  [dim]{result.api_calls} API call(s) in {result.duration_ms}ms[/dim]")
    else:
        console.print(f"  [dim]completed in {result.duration_ms}ms[/dim]")

    # ── CloudFox-style loot path announcement ──────────────────────────────
    if result.loot_path:
        from pathlib import Path as _Path
        loot_dir = _Path(result.loot_path)
        try:
            display = "~/" + str(loot_dir.relative_to(_Path.home()))
        except ValueError:
            display = str(loot_dir)
        files = "[bold]loot.csv[/bold]"
        if (loot_dir / "table.txt").exists():
            files += " • [bold]table.txt[/bold]"
        console.print(f"  [dim]📁 Loot → [cyan]{display}[/cyan]   {files}[/dim]")


def _legacy_format_result(result: TechniqueResult) -> None:
    """Hardcoded legacy formatters for techniques."""
    if result.data:
        console.print(f"  [bold green]✓[/bold green] {result.technique_id} completed")
        console.print_json(json.dumps(result.to_dict(), default=str))
    else:
        console.print(f"  [bold green]✓[/bold green] {result.technique_id} completed")


def format_techniques_list(techniques: list[RegisteredTechnique]) -> None:
    """Display available techniques as a table."""
    if not techniques:
        console.print("  No techniques loaded.", style="dim")
        return

    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("ID", style="bold cyan")
    table.add_column("Tactic", style="dim")
    table.add_column("Providers")
    table.add_column("Safe", justify="center")
    table.add_column("Description")

    for t in techniques:
        safe_icon = "[green]✓[/green]" if t.metadata.safe else "[red]✗[/red]"
        providers = ", ".join(t.metadata.providers)
        table.add_row(
            t.metadata.id,
            t.metadata.tactic,
            providers,
            safe_icon,
            t.metadata.description or "",
        )

    console.print(table)


def format_raw(data: str | None) -> None:
    """Display raw JSON data."""
    if data is None:
        console.print("  No raw data available.", style="dim")
        return
    try:
        parsed = json.loads(data)
        console.print_json(json.dumps(parsed, indent=2, default=str))
    except json.JSONDecodeError:
        console.print(data)


def format_help_menu(commands: dict | None = None, command_help_registry=None) -> None:
    """Display the categorized shell help menu.

    Args:
        commands: The active COMMANDS registry. When provided, the
                  Private / Advanced panel is only shown if the private
                  commands (exploits, payloads) are registered — i.e. the
                  private build. In the public build they are absent.
        command_help_registry: When provided, renders from the CommandHelp
                  registry (the new path) instead of the hardcoded layout.
    """
    console.print()

    if command_help_registry is not None:
        _format_help_from_registry(command_help_registry)
        return

    # --- Legacy hardcoded layout preserved below ---

    # Workspace Commands
    workspace_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    workspace_table.add_column("Command", style="bold cyan", width=35)
    workspace_table.add_column("Description")
    workspace_table.add_row("workspace create <name>", "Create a new workspace")
    workspace_table.add_row("workspace load <name>", "Load an existing workspace")
    workspace_table.add_row("workspace list", "List all workspaces")
    console.print(Panel(workspace_table, title="[bold]Workspaces[/bold]", title_align="left", border_style="blue"))

    # Credential Commands
    cred_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    cred_table.add_column("Command", style="bold cyan", width=40)
    cred_table.add_column("Description")
    cred_table.add_row("import aws --profile <name>", "Import AWS CLI profile")
    cred_table.add_row("import aws --access-key <key> --secret-key <secret>", "Import AWS keys directly")
    cred_table.add_row("import azure --default", "Import Azure default credentials")
    cred_table.add_row("import gcp --default", "Import GCP application default creds")
    cred_table.add_row("import oci --default", "Import OCI config (~/.oci/config)")
    cred_table.add_row("import entra browserdump <path>", "Import Entra tokens from browser dump")
    cred_table.add_row("import entra roadtools <path>", "Import .roadtools_auth file")
    cred_table.add_row("acquire entra device_code", "Interactive Entra login (browser)")
    cred_table.add_row("acquire entra arm", "Pivot Entra credential → Azure ARM (FOCI)")
    cred_table.add_row("export entra token", "Print raw access token")
    cred_table.add_row("export entra describe", "Decode and display JWT claims")
    cred_table.add_row("creds", "List all credentials")
    cred_table.add_row("creds --active", "List active credentials only")
    cred_table.add_row("use <id>  |  use none", "Set or clear active credential")
    cred_table.add_row("raw <id>", "Show raw JSON for a credential/principal")
    console.print(Panel(cred_table, title="[bold]Credentials[/bold]", title_align="left", border_style="green"))

    # Technique Commands
    tech_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    tech_table.add_column("Command", style="bold cyan", width=40)
    tech_table.add_column("Description")
    tech_table.add_row("techniques", "List available techniques")
    tech_table.add_row("run <technique_id> [key=value ...]", "Execute a technique")
    tech_table.add_row("<technique_id> [key=value ...]", "Shortcut — runs technique directly")
    tech_table.add_row("info <technique_id>", "Show technique details + parameters")
    tech_table.add_row("loot", "Display all saved loot from this workspace")
    tech_table.add_row("loot <technique_id>", "Display loot for a specific technique")
    tech_table.add_row("playbook list", "List available playbooks")
    tech_table.add_row("playbook run <name>", "Run a playbook (YAML sequence)")
    tech_table.add_row("reload", "Hot-reload technique modules")
    console.print(Panel(tech_table, title="[bold]Techniques[/bold]", title_align="left", border_style="magenta"))

    # Assessment & Analytics
    report_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    report_table.add_column("Command", style="bold cyan", width=40)
    report_table.add_column("Description")
    report_table.add_row("report", "Show the ATTACK_PATH.md engagement narrative")
    report_table.add_row("check-ca-bypasses", "Show aggregated bypass vectors for Conditional Access policies")
    report_table.add_row("ask <question>", "Ask the autonomous RAG Agent for advice")
    console.print(Panel(report_table, title="[bold]Report & Agent[/bold]", title_align="left", border_style="cyan"))

    # Private/Advanced — only shown when private commands are loaded
    if commands is not None and "exploits" in commands:
        adv_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
        adv_table.add_column("Command", style="bold cyan", width=35)
        adv_table.add_column("Description")
        adv_table.add_row("exploits list", "List exploit pack (initial access CVEs)")
        adv_table.add_row("exploits run <id> --param target=<url>", "Run an exploit (--safe for check-only)")
        adv_table.add_row("payloads list", "List injectable LOIS payload scripts")
        adv_table.add_row("payloads generate <name>", "Generate a keyed injection payload")
        adv_table.add_row("connect <qm://token>", "Connect to a qmd control plane (thin-client)")
        adv_table.add_row("disconnect", "Return to local mode")
        console.print(Panel(adv_table, title="[bold red]Private / Advanced[/bold red]", title_align="left", border_style="red"))

    # General
    gen_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    gen_table.add_column("Command", style="bold cyan", width=35)
    gen_table.add_column("Description")
    gen_table.add_row("help", "Show this help menu")
    gen_table.add_row("exit / quit", "Exit QM")
    console.print(Panel(gen_table, title="[bold]General[/bold]", title_align="left", border_style="white"))
    console.print()


def _format_help_from_registry(registry) -> None:
    """Render shell help by walking the CommandHelp registry, grouped by category."""
    by_cat: dict[str, list] = {}
    for help_rec in registry.values():
        by_cat.setdefault(help_rec.category, []).append(help_rec)

    category_titles = {
        "workspaces": "Workspaces",
        "credentials": "Credentials",
        "techniques": "Techniques",
        "playbooks": "Playbooks",
        "evidence": "Evidence",
        "reporting": "Reporting",
        "shell": "Shell",
        "advanced": "Advanced",
    }

    for cat_key in [
        "workspaces", "credentials", "techniques", "playbooks",
        "evidence", "reporting", "shell", "advanced",
    ]:
        records = by_cat.get(cat_key, [])
        if not records:
            continue
        tbl = Table(box=box.SIMPLE, border_style="dim", show_header=False)
        tbl.add_column("Command", style="bold cyan", width=20)
        tbl.add_column("Description")
        for rec in records:
            tbl.add_row(rec.name, rec.synopsis)
        console.print(Panel(
            tbl,
            title=f"[bold]{category_titles[cat_key]}[/bold]",
            title_align="left",
            border_style="blue",
        ))

    console.print("\n  [dim]Use `help <command>` for full details on any command.[/dim]")
    console.print("  [dim]Use `techniques` to list runnable techniques.[/dim]\n")
