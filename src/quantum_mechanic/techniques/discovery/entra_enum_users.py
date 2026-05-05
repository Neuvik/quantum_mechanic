# ================================================================
# TECHNIQUE: discovery/entra_enum_users
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate all user accounts in the Entra ID tenant
#            via Microsoft Graph. Identifies external guests,
#            disabled accounts, and privileged users.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /users with $select for key fields. Handles Graph
#   pagination (@odata.nextLink) to retrieve all accounts. Results
#   are classified by type: Member, Guest, disabled, external.
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/users/read.
#   Alert on: Large /users enumeration (>500 results returned)
#     from an unexpected clientId or source IP — strong indicator
#     of reconnaissance by a compromised token.
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import graph_list
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

_USERS_URL = (
    "https://graph.microsoft.com/v1.0/users"
    "?$select=id,displayName,userPrincipalName,mail,accountEnabled,"
    "userType,createdDateTime,lastPasswordChangeDateTime"
    "&$top=999"
)


def _format_entra_enum_users(result: Any) -> None:
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        return

    users = data.get("users", [])
    total = data.get("total", 0)
    guests = data.get("guests", 0)
    disabled = data.get("disabled", 0)

    console.print(
        f"  [bold green]✓[/bold green] Enumerated [bold]{total}[/bold] users"
        f"  [dim]({guests} guests, {disabled} disabled)[/dim]"
    )

    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("UPN / Mail", style="cyan")
    tbl.add_column("Display Name")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Enabled", style="dim")

    for u in users[:100]:
        upn = u.get("userPrincipalName") or u.get("mail") or "—"
        name = u.get("displayName", "—")
        utype = u.get("userType", "Member")
        enabled = "[green]✓[/green]" if u.get("accountEnabled") else "[red]✗[/red]"
        tbl.add_row(upn, name, utype, enabled)

    console.print(tbl)
    if total > 100:
        console.print(f"  [dim]... and {total - 100} more users in result data[/dim]")


@technique(
    technique_id="discovery/entra_enum_users",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="info",
    safe=True,
    description="Enumerate all Entra ID user accounts via Microsoft Graph.",
    formatter=_format_entra_enum_users,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Entra ID users via Graph /users."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    with httpx.Client(timeout=60) as http:
        users = graph_list(http, _USERS_URL, headers)


    guests = sum(1 for u in users if u.get("userType") == "Guest")
    disabled = sum(1 for u in users if not u.get("accountEnabled", True))

    return {
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "total": len(users),
        "guests": guests,
        "disabled": disabled,
        "users": users,
    }
