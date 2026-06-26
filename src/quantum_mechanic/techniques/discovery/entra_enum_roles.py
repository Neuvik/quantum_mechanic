# ================================================================
# TECHNIQUE: discovery/entra_enum_roles
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate all activated Directory Roles in the Entra ID
#            tenant and list the members (users, groups, SPs)
#            assigned to them.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   1. Calls GET /directoryRoles to list activated roles.
#   2. For each role, calls GET /directoryRoles/{id}/members to
#      resolve the principals assigned to it.
#
# OPSEC:     LOW — Standard Graph API calls used by legitimate apps.
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import graph_list
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "roles"
LOOT_SCHEMA = [
    ("role_name",     "Role Name",     "bold yellow"),
    ("principal_name", "Member",        "bold cyan"),
    ("principal_type", "Type",          "dim"),
    ("principal_id",   "Object ID",     "dim"),
    ("role_id",        "Role ID",       "dim"),
]

def format_roles_result(result: Any) -> None:
    """Formatter for Entra Role enumeration results."""
    from rich.table import Table
    from rich import box
    from quantum_mechanic.shell.formatters import console

    data = result.data
    roles = data.get("roles", [])
    
    if not roles:
        console.print("  [dim]No directory roles with active assignments found.[/dim]")
        return

    console.print(f"  [bold green]✓[/bold green] Discovered [bold cyan]{len(roles)}[/bold cyan] role assignment(s)")
    
    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Role Name", style="bold yellow")
    tbl.add_column("Member (UPN/Name)", style="bold cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Object ID", style="dim")

    # Sort by role name for better readability
    for r in sorted(roles, key=lambda x: x.get("role_name", "")):
        tbl.add_row(
            r.get("role_name", "Unknown"),
            r.get("principal_name", "—"),
            r.get("principal_type", "—"),
            r.get("principal_id", "—"),
        )
            
    console.print(tbl)

@technique(
    technique_id="discovery/entra_enum_roles",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="info",
    safe=True,
    description="List Entra ID directory roles and their members (users, groups, service principals).",
    formatter=format_roles_result,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Directory Role Enumeration."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "No Graph token available."}

    headers = {"Authorization": f"Bearer {token.value}"}
    assignments = []

    with httpx.Client(timeout=30) as http:
        ctx.info("Enumerating activated directory roles...")
        # 1. Get activated roles
        # Note: /directoryRoles only returns roles that have been activated/assigned.
        roles = graph_list(http, "https://graph.microsoft.com/v1.0/directoryRoles", headers)
        
        for role in roles:
            role_name = role.get("displayName", "Unknown Role")
            role_id = role.get("id")
            ctx.info(f"Resolving members for: {role_name}...")
            
            # 2. Get members for each role
            members_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members"
            members = graph_list(http, members_url, headers)
            
            for m in members:
                mtype = m.get("@odata.type", "").split(".")[-1]
                name = m.get("userPrincipalName") or m.get("displayName") or m.get("id")
                
                assignments.append({
                    "role_name": role_name,
                    "role_id": role_id,
                    "principal_name": name,
                    "principal_id": m.get("id"),
                    "principal_type": mtype
                })

    return {
        "status": "success",
        "roles": assignments,
        "tenant_id": store.tenant_id
    }
