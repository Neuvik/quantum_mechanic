# ================================================================
# TECHNIQUE: discovery/azure_enum_subscriptions
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Enumerate all Azure subscriptions accessible to the
#            current identity via ARM. Reveals the full Azure
#            blast radius of a compromised Entra identity —
#            every subscription where the principal holds any
#            RBAC role is returned.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Uses the active EntraTokenStore to acquire an ARM bearer token
#   (direct access token or FOCI expansion from a Graph refresh
#   token). Calls GET /subscriptions?api-version=2022-12-01 and
#   paginates via nextLink.
#
# DETECTION (Blue Team):
#   ARM Activity Logs: Microsoft.Resources/subscriptions/read.
#   Alert on: Bulk subscription enumeration from unexpected
#     principal — especially service principals or external
#     guest accounts. This is the first step in ARM recon.
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.arm import arm_list
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.token_store import ARM, EntraTokenStore

_SUBSCRIPTIONS_URL = (
    "https://management.azure.com/subscriptions?api-version=2022-12-01"
)

_STATE_LABELS = {
    "Enabled": "[green]Enabled[/green]",
    "Disabled": "[red]Disabled[/red]",
    "Warned": "[yellow]Warned[/yellow]",
    "Deleted": "[dim]Deleted[/dim]",
    "PastDue": "[yellow]PastDue[/yellow]",
}


def _format_azure_enum_subscriptions(result: Any) -> None:
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        return

    subs = data.get("subscriptions", [])
    total = data.get("total", 0)
    enabled = data.get("enabled_count", 0)

    console.print(
        f"  [bold green]✓[/bold green] Found [bold]{total}[/bold] subscription(s)"
        + (f"  [green]({enabled} enabled)[/green]" if enabled else "")
    )

    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("Display Name", style="cyan")
    tbl.add_column("Subscription ID", style="dim")
    tbl.add_column("State")
    tbl.add_column("Tenant ID", style="dim")

    for s in subs:
        state = s.get("state", "—")
        state_str = _STATE_LABELS.get(state, state)
        tbl.add_row(
            s.get("displayName", "—"),
            s.get("subscriptionId", "—"),
            state_str,
            s.get("tenantId", "—"),
        )

    console.print(tbl)


@technique(
    technique_id="discovery/azure_enum_subscriptions",
    tactic="discovery",
    mitre_id="T1580",
    providers=["entra"],
    severity="info",
    safe=True,
    description=(
        "Enumerate all Azure subscriptions accessible to the current identity via ARM."
    ),
    formatter=_format_azure_enum_subscriptions,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Azure subscriptions via ARM /subscriptions."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(ARM)
    if token is None:
        return {
            "error": (
                "No ARM token available. "
                "Run: acquire entra arm"
            )
        }

    if token.token_type == "refresh_token":
        token = foci_expand(store, ARM)
        if token is None:
            return {"error": "FOCI expansion for ARM failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    with httpx.Client(timeout=60) as http:
        subscriptions = arm_list(http, _SUBSCRIPTIONS_URL, headers)

    enabled_count = sum(1 for s in subscriptions if s.get("state") == "Enabled")

    return {
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "total": len(subscriptions),
        "enabled_count": enabled_count,
        "subscriptions": subscriptions,
    }
