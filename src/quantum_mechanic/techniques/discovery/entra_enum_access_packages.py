# ================================================================
# TECHNIQUE: discovery/entra_enum_access_packages
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate Identity Governance access packages and
#            their assignments. Access packages are self-service
#            privilege grants — a user can REQUEST a package and
#            get role assignments. An attacker who phishes a user
#            can request the package and elevate without ever
#            needing direct role assignment.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   1. GET /identityGovernance/entitlementManagement/accessPackages
#      for the catalog.
#   2. GET /identityGovernance/entitlementManagement/assignments
#      ?$expand=accessPackage,target for active grants.
#   3. Joins them by accessPackage.id.
#
# DETECTION (Blue Team):
#   Graph Audit Logs:
#     microsoft.graph/identityGovernance/entitlementManagement/
#     accessPackages/read
#   Alert on: Bulk read of access packages by unfamiliar clientId —
#     attacker is mapping self-service elevation surface.
#
# OPSEC:     LOW — Standard Graph API.
# SAFE:      Yes — read-only.
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

LOOT_ITEMS_KEY = "assignments"
LOOT_SCHEMA = [
    ("package_name", "Access Package", "bold yellow"),
    ("target_name", "Assignee", "bold cyan"),
    ("target_type", "Type", "dim"),
    ("state", "State", "white"),
    ("package_id", "Package ID", "dim"),
    ("assignment_id", "Assignment ID", "dim"),
]


def format_access_packages(result: Any) -> None:
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        msg = data.get("error", "Unknown error") if isinstance(data, dict) else "Unknown error"
        console.print(f"  [red]✗[/red] {msg}")
        return

    packages = data.get("packages", [])
    assignments = data.get("assignments", [])

    console.print(
        f"  [bold green]✓[/bold green] Discovered "
        f"[bold]{len(packages)}[/bold] access package(s), "
        f"[bold]{len(assignments)}[/bold] assignment(s)"
    )

    if not assignments:
        return

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Access Package", style="bold yellow")
    tbl.add_column("Assignee", style="bold cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("State", style="white")

    for a in assignments[:100]:
        tbl.add_row(
            a.get("package_name", "—"),
            a.get("target_name", "—"),
            a.get("target_type", "—"),
            a.get("state", "—"),
        )

    console.print(tbl)
    if len(assignments) > 100:
        console.print(f"  [dim]... and {len(assignments) - 100} more assignments[/dim]")


@technique(
    technique_id="discovery/entra_enum_access_packages",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="medium",
    safe=True,
    description="Enumerate Identity Governance access packages and their assignments via Graph.",
    formatter=format_access_packages,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Identity Governance access packages enumeration."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    packages_url = (
        "https://graph.microsoft.com/v1.0/identityGovernance/"
        "entitlementManagement/accessPackages"
    )
    assignments_url = (
        "https://graph.microsoft.com/v1.0/identityGovernance/"
        "entitlementManagement/assignments?$expand=accessPackage,target"
    )

    packages_out: list[dict[str, Any]] = []
    assignments_out: list[dict[str, Any]] = []

    try:
        with httpx.Client(timeout=30) as http:
            packages = graph_list(http, packages_url, headers)
            for p in packages:
                packages_out.append({
                    "package_id": p.get("id"),
                    "display_name": p.get("displayName", "—"),
                    "description": p.get("description", ""),
                })

            assignments = graph_list(http, assignments_url, headers)
            for a in assignments:
                pkg = a.get("accessPackage", {}) or {}
                target = a.get("target", {}) or {}
                assignments_out.append({
                    "package_id": pkg.get("id"),
                    "package_name": pkg.get("displayName", "—"),
                    "target_id": target.get("id"),
                    "target_name": target.get("displayName", "—"),
                    "target_type": target.get("principalType", "—"),
                    "state": a.get("state", "—"),
                    "assignment_id": a.get("id"),
                })
    except Exception as e:
        logger.warning("Access packages enumeration failed: %s", e)
        return {"error": str(e), "packages": [], "assignments": []}

    return {
        "status": "success",
        "tenant_id": store.tenant_id,
        "packages": packages_out,
        "assignments": assignments_out,
    }
