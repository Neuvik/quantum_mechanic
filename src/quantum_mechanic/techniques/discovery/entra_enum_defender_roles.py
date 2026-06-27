# ================================================================
# TECHNIQUE: discovery/entra_enum_defender_roles
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate Microsoft Defender XDR Unified RBAC
#            assignments. Defender roles can suppress alerts,
#            whitelist payloads, and disable host isolation —
#            detection evasion via legitimate RBAC.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /security/roleAssignments?$expand=principal,roleDefinition.
#   Each row is EAM-classified via classify_role_name on the
#   roleDefinition.displayName.
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/security/roleAssignments/read
#   Alert on: Bulk read by unfamiliar clientId — strong recon
#     signal because operators rarely hit /security RBAC.
#
# OPSEC:     LOW — Standard Graph API. Permission scope is rare
#            (SecurityIdentitiesSensors.Read.All), so many
#            attackers will get 403.
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
from quantum_mechanic.providers.entra.graph import graph_list
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = "assignments"
LOOT_SCHEMA = [
    ("tier", "Tier", "bold red"),
    ("role_name", "Role Name", "bold yellow"),
    ("principal_name", "Principal", "bold cyan"),
    ("principal_type", "Type", "dim"),
    ("principal_id", "Principal ID", "dim"),
    ("assignment_id", "Assignment ID", "dim"),
]


def format_defender_roles(result: Any) -> None:
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        msg = data.get("error", "Unknown error") if isinstance(data, dict) else "Unknown error"
        console.print(f"  [red]✗[/red] {msg}")
        return

    rows = data.get("assignments", [])
    if not rows:
        console.print("  [dim]No Defender role assignments found.[/dim]")
        return

    console.print(
        f"  [bold green]✓[/bold green] Discovered "
        f"[bold cyan]{len(rows)}[/bold cyan] Defender role assignment(s)"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Tier", style="bold")
    tbl.add_column("Role Name", style="bold yellow")
    tbl.add_column("Principal", style="bold cyan")
    tbl.add_column("Type", style="dim")

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
            r.get("principal_name", "—"),
            r.get("principal_type", "—"),
        )

    console.print(tbl)


@technique(
    technique_id="discovery/entra_enum_defender_roles",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="high",
    safe=True,
    description=(
        "Enumerate Microsoft Defender XDR Unified RBAC assignments "
        "with EAM tier classification."
    ),
    formatter=format_defender_roles,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Defender XDR RBAC enumeration."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    url = (
        "https://graph.microsoft.com/v1.0/security/roleAssignments"
        "?$expand=principal,roleDefinition"
    )

    results: list[dict[str, Any]] = []
    try:
        with httpx.Client(timeout=30) as http:
            assignments = graph_list(http, url, headers)
            for a in assignments:
                role_def = a.get("roleDefinition", {}) or {}
                role_name = role_def.get("displayName", "Unknown Role")
                tier = eam.classify_role_name(role_name)

                principal = a.get("principal", {}) or {}
                p_type = principal.get("@odata.type", "").split(".")[-1] or "Unknown"
                p_name = (
                    principal.get("userPrincipalName")
                    or principal.get("displayName")
                    or principal.get("id")
                )

                results.append({
                    "tier": tier,
                    "role_name": role_name,
                    "role_id": role_def.get("id"),
                    "principal_name": p_name,
                    "principal_id": principal.get("id"),
                    "principal_type": p_type,
                    "assignment_id": a.get("id"),
                })
    except Exception as e:
        logger.warning("Defender role enumeration failed: %s", e)
        return {"error": str(e), "assignments": []}

    return {
        "status": "success",
        "tenant_id": store.tenant_id,
        "assignments": results,
    }
