# ================================================================
# TECHNIQUE: discovery/entra_enum_app_perms
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1526 — Cloud Service Discovery
#
# PURPOSE:   Per-application permission drilldown. Given an app-id,
#            list every requested API permission with tier
#            classification and the resource it targets. This is
#            the follow-on drilldown to entra_enum_apps — the
#            summary shows top perms per app, this shows all.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Fetches a single /applications/<id> and its
#   requiredResourceAccess[]. Resolves each perm UUID to a
#   human name via GraphPermResolver, classifies each name via
#   EAM (ControlPlane / ManagementPlane / WorkloadPlane / etc.),
#   and renders as a table sorted by tier severity.
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/applications/read (single-app).
#   Very low volume compared to bulk enum_apps.
#
# OPSEC:     LOW — Single Graph GET per drilldown.
# SAFE:      Yes — read-only.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, ParameterType, technique
from quantum_mechanic.providers.entra import eam
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    graph_error_to_result,
)
from quantum_mechanic.providers.entra.graph_perms import GraphPermResolver
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = "permissions"
LOOT_SCHEMA = [
    ("tier", "Tier", "bold"),
    ("name", "Permission", "yellow"),
    ("kind", "Kind", "dim"),
    ("resource_display_name", "Resource", "cyan"),
    ("resource_app_id", "Resource App ID", "dim"),
]

_TIER_ORDER = {
    eam.TIER_CONTROL_PLANE: 0,
    eam.TIER_MANAGEMENT_PLANE: 1,
    eam.TIER_WORKLOAD_PLANE: 2,
    eam.TIER_USER_ACCESS: 3,
    eam.TIER_UNKNOWN: 4,
}


def _tier_style(tier: str) -> str:
    if tier == eam.TIER_CONTROL_PLANE:
        return f"[bold red]{tier}[/bold red]"
    if tier == eam.TIER_MANAGEMENT_PLANE:
        return f"[bold yellow]{tier}[/bold yellow]"
    if tier == eam.TIER_WORKLOAD_PLANE:
        return f"[cyan]{tier}[/cyan]"
    return f"[dim]{tier}[/dim]"


def _format_app_perms(result: Any) -> None:
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

    app_name = data.get("app_display_name", "unknown app")
    perms = data.get("permissions", [])

    console.print(
        f"  [bold green]✓[/bold green] [bold]{app_name}[/bold]: "
        f"[bold]{len(perms)}[/bold] permission(s) requested"
    )

    if not perms:
        console.print("  [dim]This app requests no API permissions.[/dim]")
        return

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Tier", style="bold")
    tbl.add_column("Permission", style="bold yellow")
    tbl.add_column("Kind", style="dim")
    tbl.add_column("Resource", style="cyan")

    for p in perms:
        tbl.add_row(
            _tier_style(p.get("tier", eam.TIER_UNKNOWN)),
            p.get("name", "—"),
            p.get("kind", "—"),
            p.get("resource_display_name") or p.get("resource_app_id", "—"),
        )
    console.print(tbl)


@technique(
    technique_id="discovery/entra_enum_app_perms",
    tactic="discovery",
    mitre_id="T1526",
    providers=["entra"],
    severity="info",
    safe=True,
    description=(
        "Drill down into one Entra app registration's requested API permissions."
    ),
    formatter=_format_app_perms,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "app_id",
            "Application (client) ID or object ID of the app registration.",
            required=True,
            type=ParameterType.STRING,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Fetch a single app registration and enumerate its permissions."""
    app_id = ctx.get_param("app_id")
    if not app_id:
        return {"status": "error", "error": "app_id parameter is required."}

    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"status": "error", "error": "No Graph token available."}
    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"status": "error", "error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    # Try both object-id and appId lookup. Graph's /applications supports
    # both /{id} (object id) and /{appId=guid} filter — we prefer object id
    # but fall back to a filter search if that returns 404.
    with httpx.Client(timeout=30) as http:
        primary_url = f"https://graph.microsoft.com/v1.0/applications/{app_id}"
        try:
            resp = http.get(primary_url, headers=headers)
        except Exception as exc:
            return {"status": "error", "error": f"Graph GET failed: {exc}"}

        if resp.status_code == 404:
            # Fall back to appId filter (client id GUID).
            filt_url = (
                "https://graph.microsoft.com/v1.0/applications?"
                f"$filter=appId eq '{app_id}'"
            )
            try:
                resp = http.get(filt_url, headers=headers)
            except Exception as exc:
                return {"status": "error", "error": f"Graph filter GET failed: {exc}"}
            if resp.status_code != 200:
                return {
                    "status": "denied" if 400 <= resp.status_code < 500 else "error",
                    "error": f"HTTP {resp.status_code} fetching app {app_id}",
                    "required_scope": "Application.Read.All",
                }
            body = resp.json()
            value = body.get("value", [])
            if not value:
                return {
                    "status": "error",
                    "error": f"No app registration found for id {app_id!r}",
                }
            app_obj = value[0]
        elif resp.status_code != 200:
            return {
                "status": "denied" if 400 <= resp.status_code < 500 else "error",
                "error": f"HTTP {resp.status_code} fetching app {app_id}",
                "required_scope": "Application.Read.All",
            }
        else:
            app_obj = resp.json()

        # Resolve permission UUIDs → names via the shared resolver.
        resolver = GraphPermResolver(http=http, headers=headers)
        perms: list[dict[str, Any]] = []

        try:
            for rra in app_obj.get("requiredResourceAccess", []):
                resource_app_id = rra.get("resourceAppId")
                if not resource_app_id:
                    continue
                perm_entries = rra.get("resourceAccess", [])
                names = resolver.resolve_perm_names(
                    resource_app_id=resource_app_id,
                    perm_entries=perm_entries,
                )
                # Zip resolved names back onto the entries (names is a flat list
                # aligned with the input order — same as resolver contract).
                for entry, name in zip(perm_entries, names, strict=False):
                    kind = "Application" if entry.get("type") == "Role" else "Delegated"
                    perms.append({
                        "resource_app_id": resource_app_id,
                        "resource_display_name": _WELL_KNOWN.get(resource_app_id, resource_app_id),
                        "name": name,
                        "kind": kind,
                        "tier": eam.classify_graph_permission(name),
                    })
        except GraphError as e:
            return graph_error_to_result(
                e,
                app_id=app_id,
                app_display_name=app_obj.get("displayName", "unknown"),
                permissions=[],
            )

    perms.sort(key=lambda p: _TIER_ORDER.get(p["tier"], 5))

    return {
        "status": "success",
        "app_id": app_id,
        "app_display_name": app_obj.get("displayName", "unknown"),
        "permissions": perms,
    }


# Well-known resource-app-id → display name map for readability. Extends
# the same set used by the CA policies technique.
_WELL_KNOWN = {
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph (legacy)",
    "797f4846-ba00-4fd7-ba43-dac1f8f63013": "Windows Azure Service Management API",
    "00000002-0000-0ff1-ce00-000000000000": "Office 365 Exchange Online",
    "00000003-0000-0ff1-ce00-000000000000": "Office 365 SharePoint Online",
}
