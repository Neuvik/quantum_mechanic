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
# PROVIDERS: Azure, Entra
#
# HOW IT WORKS:
#   Builds an azure.mgmt.subscription.SubscriptionClient directly off
#   ctx.session (a TokenCredential). Calls
#   subscriptions.list() to enumerate every subscription the current
#   principal can see. This works transparently whether the active
#   credential is a native "azure" TokenCredential or an "entra"
#   credential bridged to Azure by core/runner.py (which wraps it in
#   EntraTokenCredential — itself a TokenCredential implementation) —
#   no FOCI/EntraTokenStore access is required.
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

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

_STATE_LABELS = {
    "Enabled": "[green]Enabled[/green]",
    "Disabled": "[red]Disabled[/red]",
    "Warned": "[yellow]Warned[/yellow]",
    "Deleted": "[dim]Deleted[/dim]",
    "PastDue": "[yellow]PastDue[/yellow]",
}


# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "subscriptions"
LOOT_SCHEMA = [
    ("displayName", "Display Name", "bold cyan"),
    ("subscriptionId", "Subscription ID", "dim"),
    ("state", "State", "white"),
    ("tenantId", "Tenant ID", "dim"),
]


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
    providers=["azure", "entra"],
    severity="info",
    safe=True,
    description=("Enumerate all Azure subscriptions accessible to the current identity via ARM."),
    formatter=_format_azure_enum_subscriptions,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Azure subscriptions via azure.mgmt.subscription.SubscriptionClient."""
    try:
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-subscription not installed.", "subscriptions": []}

    try:
        sub_client = SubscriptionClient(ctx.session)
        raw_subs = list(sub_client.subscriptions.list())

        tenant_id = None
        try:
            tenant_id = ctx.whoami().tenant_id
        except Exception as whoami_err:
            logger.debug("whoami() failed while resolving tenant_id: %s", whoami_err)

        def _state_str(state: Any) -> str | None:
            if state is None:
                return None
            return state.value if hasattr(state, "value") else str(state)

        subscriptions = []
        for s in raw_subs:
            state = _state_str(s.state)
            subscriptions.append(
                {
                    "subscriptionId": s.subscription_id,
                    "displayName": s.display_name,
                    "state": state,
                    "tenantId": tenant_id,
                }
            )

        enabled_count = sum(1 for s in subscriptions if s["state"] == "Enabled")

        return {
            "provider": ctx.provider_name,
            "tenant_id": tenant_id,
            "total": len(subscriptions),
            "enabled_count": enabled_count,
            "subscriptions": subscriptions,
        }

    except Exception as e:
        logger.error("Azure enum_subscriptions failed: %s", e)
        return {"error": str(e), "subscriptions": []}
