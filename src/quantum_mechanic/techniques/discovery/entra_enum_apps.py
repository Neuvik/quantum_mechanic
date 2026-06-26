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
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/applications/read,
#     microsoft.graph/servicePrincipals/read.
#   Alert on: Enumeration of /applications — this reveals the full
#     OAuth app inventory, including apps with client secrets.
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
from quantum_mechanic.providers.entra.graph import graph_list
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


def _format_entra_enum_apps(result: Any) -> None:
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        return

    apps = data.get("applications", [])
    sps = data.get("service_principals", [])

    console.print(
        f"  [bold green]✓[/bold green] "
        f"[bold]{len(apps)}[/bold] app registrations, "
        f"[bold]{len(sps)}[/bold] service principals"
    )

    if apps:
        tbl = Table(title="App Registrations", box=None, padding=(0, 2), show_header=True)
        tbl.add_column("Display Name", style="cyan")
        tbl.add_column("Audience", style="dim")
        tbl.add_column("Secrets", style="yellow")
        tbl.add_column("App ID", style="dim")

        for a in apps[:50]:
            secrets = len(a.get("passwordCredentials", []))
            secret_str = f"[yellow]{secrets}[/yellow]" if secrets else "[dim]0[/dim]"
            tbl.add_row(
                a.get("displayName", "—"),
                a.get("signInAudience", "—"),
                secret_str,
                a.get("appId", ""),
            )
        console.print(tbl)
        if len(apps) > 50:
            console.print(f"  [dim]... and {len(apps) - 50} more apps in result data[/dim]")


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

    with httpx.Client(timeout=60) as http:
        applications = graph_list(http, _APPS_URL, headers)
        service_principals = graph_list(http, _SP_URL, headers)

    multi_tenant = [
        a for a in applications
        if a.get("signInAudience", "") not in ("AzureADMyOrg", "")
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
        # Resolve permission names from `_resolved_perms` (Phase A convenience).
        # Real permission UUID → name resolution lands in Phase B.
        perm_names = a.get("_resolved_perms", [])
        apps.append({
            "displayName": a.get("displayName"),
            "type": "App Registration",
            "appId": a.get("appId"),
            "signInAudience": a.get("signInAudience"),
            "secrets": len(a.get("passwordCredentials", [])),
            "enabled": "—",
            "id": a.get("id"),
            "highest_perm_tier": _highest_tier(perm_names),
        })
    for sp in service_principals:
        apps.append({
            "displayName": sp.get("displayName"),
            "type": "Service Principal",
            "appId": sp.get("appId"),
            "signInAudience": "—",
            "secrets": 0,
            "enabled": "Yes" if sp.get("accountEnabled") else "No",
            "id": sp.get("id"),
            "highest_perm_tier": eam.TIER_UNKNOWN,  # SPs resolved in Phase B
        })

    return {
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "applications": applications,
        "service_principals": service_principals,
        "apps": apps,
        "multi_tenant_count": len(multi_tenant),
        "with_secrets_count": len(with_secrets),
    }
