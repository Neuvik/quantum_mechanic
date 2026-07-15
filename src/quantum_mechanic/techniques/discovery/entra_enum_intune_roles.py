# ================================================================
# TECHNIQUE: discovery/entra_enum_intune_roles
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate Microsoft Intune (Device Management) RBAC
#            assignments. Intune Service Administrator can deploy
#            Win32 apps or PowerShell remediation scripts to every
#            enrolled device — mass code-exec from the cloud
#            control plane. Identifies this and similar Intune
#            roles + their assignees.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /deviceManagement/roleDefinitions for role names,
#   then GET /deviceManagement/roleAssignments for active grants.
#   Each row is EAM-classified via classify_role_name.
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/deviceManagement/roleAssignments/read
#   Alert on: Bulk read of Intune RBAC assignments by unfamiliar
#     clientId — strong reconnaissance signal.
#
# OPSEC:     LOW — Standard Graph API call.
# SAFE:      Yes — read-only.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra import eam
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    graph_error_to_result,
    graph_list,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = "assignments"
LOOT_SCHEMA = [
    ("tier", "Tier", "bold red"),
    ("role_name", "Role Name", "bold yellow"),
    ("display_name", "Assignment Name", "bold cyan"),
    ("members_count", "Members", "white"),
    ("role_id", "Role ID", "dim"),
    ("assignment_id", "Assignment ID", "dim"),
]


def format_intune_roles(result: Any) -> None:
    from rich import box
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

    rows = data.get("assignments", [])
    if not rows:
        console.print("  [dim]No Intune role assignments found.[/dim]")
        return

    console.print(
        f"  [bold green]✓[/bold green] Discovered "
        f"[bold cyan]{len(rows)}[/bold cyan] Intune role assignment(s)"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Tier", style="bold")
    tbl.add_column("Role Name", style="bold yellow")
    tbl.add_column("Assignment Name", style="bold cyan")
    tbl.add_column("Members", style="white")

    for r in sorted(rows, key=lambda x: x.get("tier", "Z")):
        tier = r.get("tier", "Unknown")
        if tier == eam.TIER_CONTROL_PLANE:
            color = "red"
        elif tier == eam.TIER_MANAGEMENT_PLANE:
            color = "yellow"
        else:
            color = "white"
        tbl.add_row(
            f"[{color}]{tier}[/{color}]",
            r.get("role_name", "Unknown"),
            r.get("display_name", "—"),
            str(r.get("members_count", 0)),
        )

    console.print(tbl)


@technique(
    technique_id="discovery/entra_enum_intune_roles",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="high",
    safe=True,
    description=(
        "Enumerate Microsoft Intune (Device Management) RBAC assignments "
        "with EAM tier classification."
    ),
    formatter=format_intune_roles,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Intune RBAC enumeration."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    role_defs_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions"
    role_assignments_url = "https://graph.microsoft.com/v1.0/deviceManagement/roleAssignments"

    results: list[dict[str, Any]] = []
    try:
        with httpx.Client(timeout=30) as http:
            role_defs = graph_list(http, role_defs_url, headers)
            id_to_role = {rd["id"]: rd.get("displayName", "Unknown") for rd in role_defs}

            assignments = graph_list(http, role_assignments_url, headers)
            for a in assignments:
                role_id = a.get("roleDefinitionId")
                role_name = id_to_role.get(role_id, "Unknown Role")
                tier = eam.classify_role_name(role_name)
                results.append({
                    "tier": tier,
                    "role_name": role_name,
                    "role_id": role_id,
                    "display_name": a.get("displayName", "—"),
                    "members_count": len(a.get("members", [])),
                    "assignment_id": a.get("id"),
                })
    except GraphError as e:
        logger.info("Intune roles enumeration returned %s: %s", type(e).__name__, e)
        return graph_error_to_result(e, assignments=[])
    except Exception as e:
        logger.warning("Intune role enumeration failed: %s", e)
        return {"status": "error", "error": str(e), "assignments": []}

    return {
        "status": "success",
        "tenant_id": store.tenant_id,
        "assignments": results,
    }
