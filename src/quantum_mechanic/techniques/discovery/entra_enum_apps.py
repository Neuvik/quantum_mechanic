# ================================================================
# TECHNIQUE: discovery/entra_enum_apps
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1526 — Cloud Service Discovery
#
# PURPOSE:   Enumerate Entra ID application registrations and
#            service principals. Identifies multi-tenant apps,
#            apps with high-privilege API permissions, and
#            service principals with client secrets/certificates.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /applications (app registrations owned by this tenant)
#   and GET /servicePrincipals (all SPs including third-party).
#   Both endpoints are paginated via @odata.nextLink.
#            For each Application's requiredResourceAccess, queries
#            /servicePrincipals?$filter=appId eq '<resource>' to translate
#            permission UUIDs to human-readable names (cached per resource).
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/applications/read,
#     microsoft.graph/servicePrincipals/read.
#   Alert on: Enumeration of /applications — this reveals the full
#     OAuth app inventory, including apps with client secrets.
#   Also: microsoft.graph/servicePrincipals/read filtered by appId
#         (resolver call per resource SP).
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

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
from quantum_mechanic.providers.entra.graph_perms import GraphPermResolver
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

_APPS_URL = (
    "https://graph.microsoft.com/v1.0/applications"
    "?$select=id,appId,displayName,signInAudience,createdDateTime,"
    "passwordCredentials,keyCredentials,requiredResourceAccess"
    "&$top=999"
)
_SP_URL = (
    "https://graph.microsoft.com/v1.0/servicePrincipals"
    "?$select=id,appId,displayName,servicePrincipalType,accountEnabled,"
    "appOwnerOrganizationId,createdDateTime"
    "&$top=999"
)


# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "apps"
LOOT_SCHEMA = [
    ("displayName", "Display Name", "bold cyan"),
    ("type", "Type", "white"),
    ("appId", "App ID", "dim"),
    ("signInAudience", "Audience", "dim"),
    ("secrets", "Secrets", "yellow"),
    ("highest_perm_tier", "Highest Perm Tier", "bold red"),
    ("enabled", "Enabled", "dim"),
    ("id", "Object ID", "dim"),
]


def _tier_cell(tier: str) -> str:
    """Render an EAM tier value with per-cell color coding."""
    if tier == eam.TIER_CONTROL_PLANE:
        return f"[red]{tier}[/red]"
    if tier == eam.TIER_MANAGEMENT_PLANE:
        return f"[yellow]{tier}[/yellow]"
    if tier == eam.TIER_WORKLOAD_PLANE:
        return f"[cyan]{tier}[/cyan]"
    # UserAccess + Unknown fall through to dim
    return f"[dim]{tier}[/dim]"


def _format_entra_enum_apps(result: Any) -> None:
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

    apps_raw = data.get("applications", [])
    sps = data.get("service_principals", [])

    console.print(
        f"  [bold green]✓[/bold green] "
        f"[bold]{len(apps_raw)}[/bold] app registrations, "
        f"[bold]{len(sps)}[/bold] service principals"
    )

    stats = data.get("_resolve_stats", {})
    if stats.get("attempts", 0) > 0 and stats.get("resolved", 0) == 0:
        console.print(
            "  [yellow]⚠[/yellow]  Resolved 0/{} Graph permissions — "
            "check Graph token scope (Application.Read.All recommended)".format(stats["attempts"])
        )

    # Build lookups for the enriched per-app tier and CP perm inline so
    # we can render alongside the raw Graph object fields.
    enriched_by_id = {
        row.get("appId"): row
        for row in data.get("apps", [])
        if row.get("type") == "App Registration"
    }

    if apps_raw:
        tbl = Table(title="App Registrations", box=None, padding=(0, 2), show_header=True)
        tbl.add_column("Display Name", style="cyan")
        tbl.add_column("Audience", style="dim")
        tbl.add_column("Secrets", style="yellow")
        tbl.add_column("Highest Perm Tier")
        tbl.add_column("Top CP Perms")
        tbl.add_column("App ID", style="dim")

        for a in apps_raw[:50]:
            secrets = len(a.get("passwordCredentials", []))
            secret_str = f"[yellow]{secrets}[/yellow]" if secrets else "[dim]0[/dim]"
            enriched = enriched_by_id.get(a.get("appId"), {})
            tier = enriched.get("highest_perm_tier", eam.TIER_UNKNOWN)
            top_cp = enriched.get("top_cp_perms", [])
            cp_count = enriched.get("cp_perm_count", 0)
            if top_cp:
                extra = f" +{cp_count - len(top_cp)}" if cp_count > len(top_cp) else ""
                cp_cell = "[red]" + ", ".join(top_cp) + "[/red]" + extra
            else:
                cp_cell = "[dim]—[/dim]"
            tbl.add_row(
                a.get("displayName", "—"),
                a.get("signInAudience", "—"),
                secret_str,
                _tier_cell(tier),
                cp_cell,
                a.get("appId", ""),
            )
        console.print(tbl)
        if len(apps_raw) > 50:
            console.print(
                f"  [dim]... and {len(apps_raw) - 50} more apps in result data. "
                f"Use `run discovery/entra_enum_app_perms --app-id <id>` for per-app drilldown.[/dim]"
            )
        else:
            console.print(
                "  [dim]Use `run discovery/entra_enum_app_perms --app-id <id>` "
                "for per-app permission drilldown.[/dim]"
            )


@technique(
    technique_id="discovery/entra_enum_apps",
    tactic="discovery",
    mitre_id="T1526",
    providers=["entra"],
    severity="info",
    safe=True,
    description=(
        "Enumerate Entra ID app registrations and service principals via Microsoft Graph."
    ),
    formatter=_format_entra_enum_apps,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Entra ID apps and service principals via Graph."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    try:
        with httpx.Client(timeout=60) as http:
            applications = graph_list(http, _APPS_URL, headers)
            service_principals = graph_list(http, _SP_URL, headers)

            # Resolve Graph permission UUIDs → human names on each Application.
            # The resolver caches per resource_app_id so each resource SP (Graph,
            # SharePoint, Exchange, etc.) is fetched at most once per run.
            resolver = GraphPermResolver(http=http, headers=headers)
            _resolve_attempts = 0
            _resolve_successes = 0
            for app in applications:
                resolved: list[str] = []
                for rra in app.get("requiredResourceAccess", []):
                    resource_app_id = rra.get("resourceAppId")
                    if not resource_app_id:
                        continue
                    perm_entries = rra.get("resourceAccess", [])
                    names = resolver.resolve_perm_names(
                        resource_app_id=resource_app_id,
                        perm_entries=perm_entries,
                    )
                    _resolve_attempts += len(perm_entries)
                    _resolve_successes += len(names)
                    resolved.extend(names)
                app["_resolved_perms"] = resolved
    except GraphError as e:
        return graph_error_to_result(e, applications=[], service_principals=[], apps=[])

    multi_tenant = [
        a for a in applications if a.get("signInAudience", "") not in ("AzureADMyOrg", "")
    ]
    with_secrets = [a for a in applications if a.get("passwordCredentials")]

    _tier_rank = {
        eam.TIER_CONTROL_PLANE: 0,
        eam.TIER_MANAGEMENT_PLANE: 1,
        eam.TIER_WORKLOAD_PLANE: 2,
        eam.TIER_USER_ACCESS: 3,
        eam.TIER_UNKNOWN: 4,
    }

    def _highest_tier(perm_names: list[str]) -> str:
        if not perm_names:
            return eam.TIER_UNKNOWN
        tiers = [eam.classify_graph_permission(p) for p in perm_names]
        return min(tiers, key=lambda t: _tier_rank.get(t, 4))

    apps = []
    for a in applications:
        # Resolved by GraphPermResolver above.
        perm_names = a.get("_resolved_perms", [])
        # Top ControlPlane perms surfaced inline so operators can triage
        # without opening a per-app drilldown. Only ControlPlane tier —
        # lower tiers show as their tier label only.
        cp_perms = [
            p for p in perm_names if eam.classify_graph_permission(p) == eam.TIER_CONTROL_PLANE
        ]
        apps.append(
            {
                "displayName": a.get("displayName"),
                "type": "App Registration",
                "appId": a.get("appId"),
                "signInAudience": a.get("signInAudience"),
                "secrets": len(a.get("passwordCredentials", [])),
                "enabled": "—",
                "id": a.get("id"),
                "highest_perm_tier": _highest_tier(perm_names),
                "top_cp_perms": cp_perms[:3],
                "cp_perm_count": len(cp_perms),
            }
        )
    for sp in service_principals:
        apps.append(
            {
                "displayName": sp.get("displayName"),
                "type": "Service Principal",
                "appId": sp.get("appId"),
                "signInAudience": "—",
                "secrets": 0,
                "enabled": "Yes" if sp.get("accountEnabled") else "No",
                "id": sp.get("id"),
                # Service principals do not carry requiredResourceAccess; tier resolution for
                # SPs requires appRoleAssignments enumeration (out of scope here).
                "highest_perm_tier": eam.TIER_UNKNOWN,
            }
        )

    return {
        "status": "success",
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "applications": applications,
        "service_principals": service_principals,
        "apps": apps,
        "multi_tenant_count": len(multi_tenant),
        "with_secrets_count": len(with_secrets),
        "_resolve_stats": {"attempts": _resolve_attempts, "resolved": _resolve_successes},
    }
