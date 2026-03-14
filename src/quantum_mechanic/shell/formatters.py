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
from quantum_mechanic.core.workspace import Credential
from quantum_mechanic.providers.base import WhoAmIResult

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


def format_credentials(creds: list[Credential]) -> None:
    """Display credentials as a rich table."""
    if not creds:
        console.print("  No credentials loaded. Run 'import' to add one.", style="dim")
        return

    table = Table(box=box.ROUNDED, border_style="dim")
    table.add_column("#", style="bold cyan", width=4)
    table.add_column("Provider", style="bold")
    table.add_column("Type", style="dim")
    table.add_column("Identity", style="white")
    table.add_column("Status", justify="center")

    for cred in creds:
        # --------------------------------------------------------
        # Color the status based on credential health.
        # --------------------------------------------------------
        status_style = {
            "active": "bold green",
            "expiring": "bold yellow",
            "expired": "bold red",
            "revoked": "bold red",
        }.get(cred.status, "dim")

        identity = cred.friendly_name or cred.principal_id or "unknown"

        table.add_row(
            str(cred.id),
            cred.provider.upper(),
            cred.credential_type,
            identity,
            Text(cred.status, style=status_style),
        )

    console.print(table)


def format_whoami_result(result: WhoAmIResult) -> None:
    """Display a whoami result as a structured panel."""
    lines = []
    lines.append(f"[bold]Provider:[/bold]  {result.provider.upper()}")
    lines.append(f"[bold]Identity:[/bold]  {result.friendly_name}")
    lines.append(f"[bold]Type:[/bold]      {result.principal_type}")
    lines.append(f"[bold]Account:[/bold]   {result.account_id}")
    if result.account_name:
        lines.append(f"[bold]Acct Name:[/bold] {result.account_name}")
    if result.tenant_id:
        lines.append(f"[bold]Tenant:[/bold]    {result.tenant_id}")

    if result.extra:
        if "subscriptions" in result.extra:
            subs = result.extra["subscriptions"]
            if subs:
                lines.append(f"\n[bold]Subscriptions:[/bold] ({len(subs)})")
                for s in subs:
                    lines.append(f"  • {s.get('name', 'unnamed')} ({s.get('id', '?')})")
        if "user_id" in result.extra:
            lines.append(f"[bold]User ID:[/bold]   {result.extra['user_id']}")

    lines.append("\n[dim]Stored to workspace ✓[/dim]")

    title = f"[bold]CREDENTIAL — {result.provider.upper()} {result.principal_type.title()}[/bold]"
    console.print(
        Panel(
            "\n".join(lines),
            title=title,
            border_style="green",
            expand=False,
        )
    )


def format_technique_result(result: TechniqueResult) -> None:
    """Display a technique result."""
    if result.status == "error":
        console.print(f"  [bold red]✗[/bold red] {result.error}")
        return

    if isinstance(result.data, WhoAmIResult):
        format_whoami_result(result.data)
    elif result.technique_id == "discovery/enum_iam" and isinstance(result.data, dict):
        format_enum_iam_result(result)
    elif result.technique_id == "discovery/enum_compute" and isinstance(result.data, dict):
        format_enum_compute_result(result)
    else:
        console.print(f"  [bold green]✓[/bold green] {result.technique_id} completed")
        if result.data:
            console.print_json(json.dumps(result.to_dict(), default=str))

    console.print(f"  [dim]{result.api_calls} API call(s) in {result.duration_ms}ms[/dim]")


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


def format_enum_compute_result(result: TechniqueResult) -> None:
    """Display compute instances as a clean Rich table.

    Shows: Instance ID, State, Type (size), Private IP, Public IP,
    Instance Profile (name only, ARN is verbose).
    """
    data = result.data
    provider = result.provider
    instances = data.get("instances", [])
    total = data.get("total", len(instances))

    console.print(
        f"  [bold green]✓[/bold green] {total} compute instance(s) found — [dim]{provider.upper()}[/dim]"
    )

    if not instances:
        console.print("  [dim]No instances with attached identities found.[/dim]")
        return

    if provider == "aws":
        tbl = Table(box=box.ROUNDED, border_style="dim")
        tbl.add_column("Instance ID", style="cyan")
        tbl.add_column("State", justify="center")
        tbl.add_column("Type", style="dim")
        tbl.add_column("Private IP")
        tbl.add_column("Public IP")
        tbl.add_column("Instance Profile", style="yellow")

        for inst in instances:
            state = inst.get("state", "?")
            state_style = "green" if state == "running" else ("red" if state == "terminated" else "dim")
            # Show profile name only — shorten 'arn:aws:iam::123:instance-profile/Foo' → 'Foo'
            profile_arn = inst.get("instance_profile_arn") or ""
            profile_name = profile_arn.split("/")[-1] if "/" in profile_arn else profile_arn
            tbl.add_row(
                inst.get("instance_id", "?"),
                f"[{state_style}]{state}[/{state_style}]",
                inst.get("type", "?"),
                inst.get("private_ip") or "—",
                inst.get("public_ip") or "—",
                profile_name or "—",
            )
        console.print(tbl)

    elif provider == "azure":
        tbl = Table(box=box.ROUNDED, border_style="dim")
        tbl.add_column("VM Name", style="cyan")
        tbl.add_column("Location", style="dim")
        tbl.add_column("Identity Type", style="yellow")
        tbl.add_column("System-Assigned Principal")
        for inst in instances:
            tbl.add_row(
                inst.get("name", "?"),
                inst.get("location", "?"),
                inst.get("identity_type", "?"),
                inst.get("system_assigned_principal_id") or "—",
            )
        console.print(tbl)

    elif provider == "gcp":
        tbl = Table(box=box.ROUNDED, border_style="dim")
        tbl.add_column("Instance", style="cyan")
        tbl.add_column("Zone", style="dim")
        tbl.add_column("Machine Type", style="dim")
        tbl.add_column("Service Account", style="yellow")
        for inst in instances:
            sas = inst.get("service_accounts", [])
            sa_str = sas[0]["email"].split("@")[0] if sas else "—"
            tbl.add_row(
                inst.get("name", "?"),
                inst.get("zone", "?"),
                inst.get("machine_type", "?"),
                sa_str,
            )
        console.print(tbl)

    elif provider == "oci":
        tbl = Table(box=box.ROUNDED, border_style="dim")
        tbl.add_column("Instance", style="cyan")
        tbl.add_column("State", justify="center")
        tbl.add_column("Shape", style="dim")
        tbl.add_column("Region", style="dim")
        for inst in instances:
            state = inst.get("lifecycle_state", "?")
            state_style = "green" if state == "RUNNING" else "dim"
            tbl.add_row(
                inst.get("display_name") or inst.get("instance_id", "?"),
                f"[{state_style}]{state}[/{state_style}]",
                inst.get("shape", "?"),
                inst.get("region", "?"),
            )
        console.print(tbl)



def format_enum_iam_result(result: TechniqueResult) -> None:
    """Format the results of the IAM enumeration technique into Rich tables."""
    data = result.data
    provider = result.provider
    principal = data.get("principal", "unknown")
    principal_type = data.get("principal_type", "unknown")

    console.print(f"  [bold green]✓[/bold green] IAM Enumeration for {provider.upper()} {principal_type} [cyan]{principal}[/cyan]")

    if provider == "aws":
        attached_policies = data.get("attached_policies", [])
        inline_policies = data.get("inline_policies", [])
        
        if not attached_policies and not inline_policies:
            console.print("  [dim]No attached or inline IAM policies found.[/dim]")
            return

        if attached_policies:
            table = Table(box=box.ROUNDED, border_style="dim", title="Attached Managed Policies", title_style="bold cyan")
            table.add_column("Policy Name", style="white")
            table.add_column("Policy ARN", style="dim")
            for p in attached_policies:
                table.add_row(p.get("PolicyName", ""), p.get("PolicyArn", ""))
            console.print(table)
            
        if inline_policies:
            table = Table(box=box.ROUNDED, border_style="dim", title="Inline Policies", title_style="bold yellow")
            table.add_column("Policy Name", style="white")
            for p in inline_policies:
                table.add_row(p.get("PolicyName", ""))
            console.print(table)

    elif provider == "azure":
        assignments = data.get("role_assignments", [])
        if not assignments:
            console.print("  [dim]No Azure role assignments found.[/dim]")
            return
            
        table = Table(box=box.ROUNDED, border_style="dim", title="Azure Role Assignments", title_style="bold cyan")
        table.add_column("Role Name", style="bold white")
        table.add_column("Scope", style="dim")
        table.add_column("Definition ID", style="dim")
        for a in assignments:
            table.add_row(a.get("roleName", "Unknown"), a.get("scope", ""), str(a.get("roleDefinitionId", "")))
        console.print(table)

    elif provider == "gcp":
        roles = data.get("project_roles", [])
        if not roles:
            console.print("  [dim]No GCP IAM roles found.[/dim]")
            return
            
        table = Table(box=box.ROUNDED, border_style="dim", title="GCP Project Roles", title_style="bold cyan")
        table.add_column("Project", style="bold white")
        table.add_column("Role", style="green")
        table.add_column("Condition", style="dim")
        for r in roles:
            condition = r.get("condition") or "None"
            table.add_row(r.get("project", ""), r.get("role", ""), str(condition))
        console.print(table)

    elif provider == "oci":
        groups = data.get("groups", [])
        policies = data.get("tenancy_policies", [])
        
        if not groups and not policies:
            console.print("  [dim]No OCI groups or tenancy policies found.[/dim]")
            return

        if groups:
            table = Table(box=box.ROUNDED, border_style="dim", title="OCI Group Memberships", title_style="bold cyan")
            table.add_column("Group Name", style="bold white")
            table.add_column("Group ID", style="dim")
            for g in groups:
                table.add_row(g.get("name", ""), g.get("id", ""))
            console.print(table)
            
        if policies:
            table = Table(box=box.ROUNDED, border_style="dim", title="OCI Tenancy Policies", title_style="bold yellow")
            table.add_column("Policy Name", style="bold white")
            table.add_column("Statements", style="green")
            for p in policies:
                statements = "\n".join(p.get("statements", []))
                table.add_row(p.get("name", ""), statements)
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


def format_help_menu(commands: dict | None = None) -> None:
    """Display the categorized shell help menu.

    Args:
        commands: The active COMMANDS registry. When provided, the
                  Private / Advanced panel is only shown if the private
                  commands (exploits, payloads) are registered — i.e. the
                  private build. In the public build they are absent.
    """
    console.print()

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
    cred_table.add_column("Command", style="bold cyan", width=35)
    cred_table.add_column("Description")
    cred_table.add_row("import aws --profile <name>", "Import AWS CLI profile")
    cred_table.add_row("import azure --default", "Import Azure default credentials")
    cred_table.add_row("import gcp --default", "Import GCP application default creds")
    cred_table.add_row("import gcp --key-file <path>", "Import GCP service account key")
    cred_table.add_row("import oci --default", "Import OCI config (~/.oci/config)")
    cred_table.add_row("import oci --profile <name>", "Import OCI named profile")
    cred_table.add_row("creds", "List all credentials")
    cred_table.add_row("creds --active", "List active credentials only")
    cred_table.add_row("creds delete <id>", "Delete a credential")
    cred_table.add_row("use <id>", "Set active credential")
    cred_table.add_row("raw <id>", "Show raw JSON for a credential/principal")
    console.print(Panel(cred_table, title="[bold]Credentials[/bold]", title_align="left", border_style="green"))

    # Technique Commands
    tech_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    tech_table.add_column("Command", style="bold cyan", width=35)
    tech_table.add_column("Description")
    tech_table.add_row("techniques", "List available techniques")
    tech_table.add_row("run <id> [--param k=v]", "Execute a technique")
    tech_table.add_row("<id>", "Shortcut — runs technique directly")
    tech_table.add_row("help <id>", "Show technique details")
    tech_table.add_row("reload", "Hot-reload technique modules")
    console.print(Panel(tech_table, title="[bold]Techniques[/bold]", title_align="left", border_style="magenta"))

    # Assessment & Analytics
    report_table = Table(box=box.SIMPLE, border_style="dim", show_header=False)
    report_table.add_column("Command", style="bold cyan", width=35)
    report_table.add_column("Description")
    report_table.add_row("report", "Show the ATTACK_PATH.md engagement narrative")
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
