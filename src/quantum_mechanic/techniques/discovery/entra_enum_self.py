# ================================================================
# TECHNIQUE: discovery/entra_context
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Immediately after initial access, determine the identity
#            context of the compromised principal. Maps groups,
#            directory roles, and owned objects (escalation paths).
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   1. Calls GET /me to get basic user details.
#   2. Calls GET /me/memberOf to list groups and directory roles.
#   3. Calls GET /me/ownedObjects to find Apps/SPs owned by the user.
#
# OPSEC:     LOW — Standard Graph API calls used by legitimate apps.
# SAFE:      Yes
# ================================================================

from __future__ import annotations

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import graph_list
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

def _format_entra_context(result: Any) -> None:
    """Formatter for Entra Context results."""
    from rich.table import Table
    from rich.panel import Panel
    from quantum_mechanic.shell.formatters import console

    data = result.data
    user = data.get("user", {})
    
    # 1. Identity Panel
    id_tbl = Table(box=None, padding=(0, 2))
    id_tbl.add_column("Property", style="bold white")
    id_tbl.add_column("Value")
    id_tbl.add_row("UPN", f"[bold cyan]{user.get('userPrincipalName')}[/bold cyan]")
    id_tbl.add_row("Display Name", user.get("displayName"))
    id_tbl.add_row("Object ID", f"[dim]{user.get('id')}[/dim]")
    id_tbl.add_row("User Type", user.get("userType", "Member"))
    
    console.print(Panel(id_tbl, title="[bold]Identity Context[/bold]", border_style="blue", expand=False))

    # 2. Memberships (Groups & Roles)
    roles = data.get("roles", [])
    groups = data.get("groups", [])
    
    if roles or groups:
        mem_tbl = Table(box=None, padding=(0, 2), show_header=True)
        mem_tbl.add_column("Type", style="dim")
        mem_tbl.add_column("Name", style="bold yellow")
        mem_tbl.add_column("ID", style="dim")
        
        for r in roles:
            mem_tbl.add_row("Directory Role", r.get("displayName"), r.get("id"))
        for g in groups:
            mem_tbl.add_row("Group", g.get("displayName"), g.get("id"))
            
        console.print(Panel(mem_tbl, title="[bold]Memberships[/bold]", border_style="yellow", expand=False))

    # 3. Escalation Paths (Owned Objects)
    owned = data.get("owned_objects", [])
    if owned:
        own_tbl = Table(box=None, padding=(0, 2), show_header=True)
        own_tbl.add_column("Object Type", style="dim")
        own_tbl.add_column("Display Name", style="bold green")
        own_tbl.add_column("App ID / ID", style="cyan")
        
        for o in owned:
            otype = o.get("@odata.type", "").split(".")[-1]
            name = o.get("displayName", "—")
            # Applications have an appId, ServicePrincipals usually don't in this view
            app_id = o.get("appId", o.get("id"))
            own_tbl.add_row(otype, name, app_id)
            
        console.print(Panel(own_tbl, title="[bold]Escalation Paths (Owned Objects)[/bold]", border_style="green", expand=False))
        console.print("  [dim]Tip: Use 'run escalation/entra_app_creds' on an owned Application to escalate.[/dim]")

@technique(
    technique_id="discovery/entra_enum_self",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="info",
    safe=True,
    description="Map the identity, groups, and owned objects of the current user.",
    formatter=_format_entra_context,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Identity Context Discovery."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "No Graph token available and FOCI expansion failed."}

    headers = {"Authorization": f"Bearer {token.value}"}
    results: dict[str, Any] = {"provider": "entra"}

    with httpx.Client(timeout=30) as http:
        # 1. Get Me
        resp = http.get("https://graph.microsoft.com/v1.0/me", headers=headers)
        if resp.status_code == 200:
            results["user"] = resp.json()
        else:
            ctx.warn(f"Failed to retrieve user profile from /me (HTTP {resp.status_code}): {resp.text}")
        
        # 2. Get Memberships (Groups and Roles)
        # Note: /memberOf returns both groups and directory roles
        memberships = graph_list(http, "https://graph.microsoft.com/v1.0/me/memberOf", headers)
        results["roles"] = [m for m in memberships if m.get("@odata.type") == "#microsoft.graph.directoryRole"]
        results["groups"] = [m for m in memberships if m.get("@odata.type") == "#microsoft.graph.group"]

        # 3. Get Owned Objects
        results["owned_objects"] = graph_list(http, "https://graph.microsoft.com/v1.0/me/ownedObjects", headers)

    return results
