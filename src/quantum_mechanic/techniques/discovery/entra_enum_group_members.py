# ================================================================
# TECHNIQUE: discovery/entra_enum_group_members
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1069.003 — Cloud Groups
#
# PURPOSE:   Enumerate the members (users, groups, SPs) of a specific
#            Entra ID group. Helps map access for high-value groups
#            discovered during initial enumeration.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /groups/{id}/members (or /transitiveMembers when
#   --transitive is set, to expand nested group memberships).
#   Handles Graph pagination.
#
# OPSEC:     LOW — Standard Graph API calls used by legitimate apps.
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, ParameterType, technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import graph_list
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "members"
LOOT_SCHEMA = [
    ("group_id",      "Group ID",      "dim"),
    ("member_name",   "Member Name",   "bold cyan"),
    ("member_type",   "Type",          "dim"),
    ("member_id",     "Object ID",     "dim"),
]

def format_group_members_result(result: Any) -> None:
    """Formatter for Entra Group Member enumeration results."""
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    members = data.get("members", [])
    group_name = data.get("group_name", "Unknown Group")

    if not members:
        console.print(f"  [dim]No members found for group '{group_name}'.[/dim]")
        return

    console.print(
        f"  [bold green]✓[/bold green] Discovered "
        f"[bold cyan]{len(members)}[/bold cyan] member(s) in group "
        f"'[bold yellow]{group_name}[/bold yellow]'"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Member (UPN/Name)", style="bold cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Object ID", style="dim")

    for m in members:
        tbl.add_row(
            m.get("member_name", "—"),
            m.get("member_type", "—"),
            m.get("member_id", "—"),
        )

    console.print(tbl)

@technique(
    technique_id="discovery/entra_enum_group_members",
    tactic="discovery",
    mitre_id="T1069.003",
    providers=["entra"],
    severity="info",
    safe=True,
    description="List all members of a specific Entra ID group.",
    formatter=format_group_members_result,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "group_id",
            "The Object ID of the target group.",
            required=True,
            type=ParameterType.STRING,
            example="00000000-0000-0000-0000-000000000000"
        ),
        Parameter(
            "transitive",
            "Expand nested group memberships recursively via Graph transitiveMembers.",
            required=False,
            type=ParameterType.BOOLEAN,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Group Member Enumeration."""
    group_id = ctx.get_param("group_id")

    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "No Graph token available."}

    headers = {"Authorization": f"Bearer {token.value}"}
    results = []
    group_name = group_id

    with httpx.Client(timeout=30) as http:
        # 1. Try to get the group name first for better reporting
        group_name_url = (
            f"https://graph.microsoft.com/v1.0/groups/{group_id}"
            "?$select=displayName"
        )
        try:
            resp = http.get(group_name_url, headers=headers)
            if resp.status_code == 200:
                group_name = resp.json().get("displayName", group_id)
        except Exception as exc:
            logger.debug("Failed to get group displayName: %s", exc)

        # 2. List members
        ctx.info(f"Enumerating members for group: {group_name}...")
        transitive = bool(ctx.get_param("transitive"))
        endpoint = "transitiveMembers" if transitive else "members"
        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/{endpoint}"
        members = graph_list(http, url, headers)

        for m in members:
            mtype = m.get("@odata.type", "").split(".")[-1]
            name = m.get("userPrincipalName") or m.get("displayName") or m.get("id")

            results.append({
                "group_id": group_id,
                "group_name": group_name,
                "member_name": name,
                "member_id": m.get("id"),
                "member_type": mtype
            })

    return {
        "status": "success",
        "group_name": group_name,
        "members": results,
        "tenant_id": store.tenant_id
    }
