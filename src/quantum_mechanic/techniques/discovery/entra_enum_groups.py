# ================================================================
# TECHNIQUE: discovery/entra_enum_groups
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1069.003 — Cloud Groups
#
# PURPOSE:   Enumerate Entra ID groups and classify by type:
#            Security, Microsoft 365, Dynamic, Role-Assignable.
#            Identifies high-value groups (privileged role groups,
#            dynamic membership rules that could be abused).
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /groups with $select for key fields. Handles Graph
#   pagination. Classifies each group by groupTypes array and
#   securityEnabled / mailEnabled flags.
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/groups/read.
#   Alert on: Bulk group enumeration from unexpected source —
#     all groups visible to the token, including privileged ones.
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    graph_error_to_result,
    graph_list,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, OAUTH_REFRESH, EntraTokenStore

_GROUPS_URL = (
    "https://graph.microsoft.com/v1.0/groups"
    "?$select=id,displayName,description,groupTypes,securityEnabled,"
    "mailEnabled,isAssignableToRole,membershipRule,createdDateTime"
    "&$top=999"
)


# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "groups"
LOOT_SCHEMA = [
    ("displayName", "Display Name", "bold cyan"),
    ("group_type", "Type", "white"),
    ("isAssignableToRole", "Role-Assignable", "bold yellow"),
    ("id", "Object ID", "dim"),
    ("description", "Description", "dim"),
]


def _classify_group(g: dict) -> str:
    group_types = g.get("groupTypes", [])
    if g.get("isAssignableToRole"):
        return "role-assignable"
    if "DynamicMembership" in group_types and "Unified" in group_types:
        return "M365-dynamic"
    if "DynamicMembership" in group_types:
        return "security-dynamic"
    if "Unified" in group_types:
        return "M365"
    if g.get("securityEnabled") and not g.get("mailEnabled"):
        return "security"
    return "other"


def _format_entra_enum_groups(result: Any) -> None:
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict):
        console.print("  [red]✗[/red] Unknown error")
        return
    status = data.get("status", "success" if "error" not in data else "error")
    if status in ("denied", "error"):
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        if data.get("required_scope"):
            console.print(f"    [dim]Required scope: {data['required_scope']}[/dim]")
        return

    groups = data.get("groups", [])
    total = data.get("total", 0)
    by_type = data.get("by_type", {})

    console.print(f"  [bold green]✓[/bold green] Enumerated [bold]{total}[/bold] groups")
    for gtype, count in sorted(by_type.items()):
        console.print(f"    [dim]{gtype}:[/dim] {count}")

    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("Display Name", style="cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Role-Assignable", style="yellow")
    tbl.add_column("ID", style="dim")

    for g in groups[:100]:
        role_flag = "[bold yellow]YES[/bold yellow]" if g.get("isAssignableToRole") else ""
        tbl.add_row(
            g.get("displayName", "—"),
            g.get("group_type", "—"),
            role_flag,
            g.get("id", ""),
        )

    console.print(tbl)
    if total > 100:
        console.print(f"  [dim]... and {total - 100} more groups in result data[/dim]")


@technique(
    technique_id="discovery/entra_enum_groups",
    tactic="discovery",
    mitre_id="T1069.003",
    providers=["entra"],
    severity="info",
    safe=True,
    description="Enumerate Entra ID groups and classify by type via Microsoft Graph.",
    formatter=_format_entra_enum_groups,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Entra ID groups via Graph /groups."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == OAUTH_REFRESH:
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    try:
        with httpx.Client(timeout=60) as http:
            groups = graph_list(http, _GROUPS_URL, headers)
    except GraphError as e:
        return graph_error_to_result(e, groups=[], total=0, by_type={})

    by_type: dict[str, int] = {}
    for g in groups:
        gtype = _classify_group(g)
        g["group_type"] = gtype
        by_type[gtype] = by_type.get(gtype, 0) + 1

    return {
        "status": "success",
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "total": len(groups),
        "by_type": by_type,
        "groups": groups,
        "next_steps": [
            {
                "command": "run collection/entra_export_bloodhound",
                "reason": "Export collected groups into BloodHound OpenGraph.",
            },
        ]
        if groups
        else [],
    }
