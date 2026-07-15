# ================================================================
# TECHNIQUE: discovery/entra_enum_privileged_roles
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Identify ControlPlane / ManagementPlane identities in Entra ID
#            via the Enterprise Access Model (EAM) classifier.
#            Enumerates directory roles with a focus on administrative
#            privileges, PIM eligibility, and non-human principals.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   1. Fetches directory role definitions to map IDs to names.
#   2. Enumerates all role assignments via /roleManagement/directory/roleAssignments.
#   3. (Optional) Probes /roleManagement/directory/roleEligibilitySchedules
#      to identify users eligible for roles via PIM.
#   4. Categorizes results via EAM (ControlPlane / ManagementPlane / etc.).
#
# OPSEC:     LOW — Standard Graph API queries.
# SAFE:      Yes
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

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "assignments"
LOOT_SCHEMA = [
    ("tier",           "Tier",           "bold red"),
    ("role_name",      "Role Name",      "bold yellow"),
    ("principal_name", "Principal",      "bold cyan"),
    ("principal_type", "Type",           "dim"),
    ("assignment_type", "Assignment",     "white"),
    ("principal_id",   "Object ID",      "dim"),
]

def format_privileged_roles(result: Any) -> None:
    """Formatter for Privileged Role discovery results."""
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    status = data.get("status", "success" if "error" not in data else "error")
    if status in ("denied", "error"):
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        if data.get("required_scope"):
            console.print(f"    [dim]Required scope: {data['required_scope']}[/dim]")
        return
    assignments = data.get("assignments", [])

    if not assignments:
        console.print("  [dim]No privileged role assignments found.[/dim]")
        return

    console.print(
        f"  [bold green]✓[/bold green] Discovered "
        f"[bold cyan]{len(assignments)}[/bold cyan] privileged assignment(s)"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Tier", style="bold")
    tbl.add_column("Role Name", style="bold yellow")
    tbl.add_column("Principal", style="bold cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Assignment", style="white")

    # Sort by Tier then Role Name
    sorted_data = sorted(assignments, key=lambda x: (x.get("tier", "Z"), x.get("role_name", "")))

    for a in sorted_data:
        tier = a.get("tier", eam.TIER_UNKNOWN)
        if tier == eam.TIER_CONTROL_PLANE:
            t_color = "red"
        elif tier == eam.TIER_MANAGEMENT_PLANE:
            t_color = "yellow"
        else:
            t_color = "white"

        tbl.add_row(
            f"[{t_color}]{tier}[/{t_color}]",
            a.get("role_name", "Unknown"),
            a.get("principal_name", "—"),
            a.get("principal_type", "—"),
            a.get("assignment_type", "Permanent")
        )

    console.print(tbl)

@technique(
    technique_id="discovery/entra_enum_privileged_roles",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="high",
    safe=True,
    description=(
        "Deep discovery of privileged Entra ID roles (EAM-classified), "
        "Service Principals, and PIM eligibility."
    ),
    formatter=format_privileged_roles,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Privileged Role Discovery."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}
    results = []

    role_defs_url = (
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    )
    role_assignments_url = (
        "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        "?$expand=principal"
    )
    role_eligibility_url = (
        "https://graph.microsoft.com/v1.0/roleManagement/directory/"
        "roleEligibilitySchedules?$expand=principal"
    )

    with httpx.Client(timeout=30) as http:
        ctx.info("Resolving directory role definitions...")
        # 1. Get role definitions to map IDs
        try:
            role_defs = graph_list(http, role_defs_url, headers)
        except GraphError as e:
            return graph_error_to_result(e, assignments=[])
        id_to_role = {rd["id"]: rd["displayName"] for rd in role_defs}

        ctx.info("Enumerating active role assignments...")
        # 2. Get active role assignments
        try:
            assignments = graph_list(http, role_assignments_url, headers)
        except GraphError as e:
            return graph_error_to_result(e, assignments=[])

        for a in assignments:
            role_id = a.get("roleDefinitionId")
            role_name = id_to_role.get(role_id, "Unknown Role")

            # Classify role via EAM (ControlPlane / ManagementPlane / etc.)
            tier = eam.classify_role_name(role_name)

            principal = a.get("principal", {})
            p_type = principal.get("@odata.type", "").split(".")[-1] or "Unknown"
            p_name = (
                principal.get("userPrincipalName")
                or principal.get("displayName")
                or a.get("principalId")
            )

            results.append({
                "tier": tier,
                "role_name": role_name,
                "role_id": role_id,
                "principal_name": p_name,
                "principal_id": a.get("principalId"),
                "principal_type": p_type,
                "assignment_type": "Active/Permanent"
            })

        # 3. Try to get PIM eligibility (Role Eligibility Schedules)
        # This requires more permissions but is high value.
        try:
            ctx.info("Probing PIM eligibility schedules...")
            eligible = graph_list(http, role_eligibility_url, headers)
        except GraphError as ex:
            ctx.debug(f"PIM eligibility probe denied/failed: {ex}")
            eligible = []
        for e in eligible:
            role_id = e.get("roleDefinitionId")
            role_name = id_to_role.get(role_id, "Unknown Role")
            tier = eam.classify_role_name(role_name)

            principal = e.get("principal", {})
            p_type = principal.get("@odata.type", "").split(".")[-1] or "Unknown"
            p_name = (
                principal.get("userPrincipalName")
                or principal.get("displayName")
                or e.get("principalId")
            )

            results.append({
                "tier": tier,
                "role_name": role_name,
                "role_id": role_id,
                "principal_name": p_name,
                "principal_id": e.get("principalId"),
                "principal_type": p_type,
                "assignment_type": "Eligible (PIM)"
            })

    return {
        "provider": "entra",
        "status": "success",
        "assignments": results,
        "tenant_id": store.tenant_id
    }
