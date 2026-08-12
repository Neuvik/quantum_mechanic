# ================================================================
# TECHNIQUE: discovery/azure_enum_resource_groups
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Enumerate all Azure resource groups across all
#            accessible subscriptions via ARM. Surfaces the full
#            environment topology — names, locations, tags, and
#            resource counts per group.
#
#            A prerequisite for targeted techniques that require a
#            resource group scope (vm_execute_command, keyvault
#            enumeration, storage enumeration).
#
# PROVIDERS: Azure, Entra (Azure SDK, same pattern as azure_enum_subscriptions)
#
# HOW IT WORKS:
#   1. Builds an azure.mgmt.subscription.SubscriptionClient directly
#      off ctx.session (a TokenCredential) and calls
#      subscriptions.list() to discover all accessible subscriptions.
#   2. For each enabled subscription, builds an
#      azure.mgmt.resource.ResourceManagementClient and calls
#      resource_groups.list() to enumerate all resource groups.
#   3. In the same pass, calls resources.list() and groups the count
#      by resource group name (parsed out of each resource's `.id`).
#   This works transparently whether the active credential is a
#   native "azure" TokenCredential or an "entra" credential bridged
#   to Azure by core/runner.py (EntraTokenCredential) — no
#   FOCI/EntraTokenStore access is required.
#
# DETECTION (Blue Team):
#   ARM Activity Logs:
#     Microsoft.Resources/subscriptions/resourceGroups/read
#     Microsoft.Resources/subscriptions/resources/read
#   Alert on: Rapid enumeration of resource groups across multiple
#   subscriptions by a non-infrastructure identity. Common first
#   step in an IaaS pivot after initial Entra compromise.
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "resource_groups"
LOOT_SCHEMA = [
    ("name",               "Name",         "bold cyan"),
    ("location",           "Location",     "dim"),
    ("subscription_id",    "Subscription", "dim"),
    ("provisioning_state", "State",        "green"),
    ("resource_count",     "Resources",    "white"),
]


def _format_resource_groups(result: Any) -> None:
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        return

    groups = data.get("resource_groups", [])
    total = data.get("total", 0)
    sub_count = data.get("subscription_count", 0)

    console.print(
        f"  [bold green]✓[/bold green] Found [bold]{total}[/bold] resource group(s)"
        f" across [bold]{sub_count}[/bold] subscription(s)"
    )

    if not groups:
        return

    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("Name", style="cyan")
    tbl.add_column("Location", style="dim")
    tbl.add_column("Subscription", style="dim")
    tbl.add_column("State", style="green")
    tbl.add_column("Resources", style="white")

    for g in groups:
        tbl.add_row(
            g.get("name", "—"),
            g.get("location", "—"),
            g.get("subscription_id", "—"),
            g.get("provisioning_state", "—"),
            str(g.get("resource_count", 0)),
        )

    console.print(tbl)


@technique(
    technique_id="discovery/azure_enum_resource_groups",
    tactic="discovery",
    mitre_id="T1580",
    providers=["azure", "entra"],
    severity="info",
    safe=True,
    description=(
        "Enumerate all Azure resource groups across accessible subscriptions via ARM. "
        "Reveals environment topology and resource counts."
    ),
    formatter=_format_resource_groups,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Azure resource groups via the Azure SDK.

    Uses SubscriptionClient to discover subscriptions and
    ResourceManagementClient (per subscription) to enumerate resource
    groups and count resources per group.
    """
    try:
        from azure.mgmt.resource.resources import ResourceManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {
            "error": "azure-mgmt-resource / azure-mgmt-subscription not installed.",
            "resource_groups": [],
        }

    try:
        tenant_id = None
        try:
            tenant_id = ctx.whoami().tenant_id
        except Exception as whoami_err:
            logger.debug("whoami() failed while resolving tenant_id: %s", whoami_err)

        def _state_str(state: Any) -> str | None:
            if state is None:
                return None
            return state.value if hasattr(state, "value") else str(state)

        sub_client = SubscriptionClient(ctx.session)
        raw_subs = list(sub_client.subscriptions.list())
        enabled_subs = [s for s in raw_subs if _state_str(s.state) == "Enabled"]

        ctx.info(f"Enumerating resource groups across {len(enabled_subs)} subscription(s)...")

        resource_groups: list[dict] = []
        for sub in enabled_subs:
            sub_id = sub.subscription_id
            sub_name = sub.display_name or sub_id

            resource_client = ResourceManagementClient(ctx.session, sub_id)

            # 1. Enumerate resource groups in this subscription
            rgs = list(resource_client.resource_groups.list())

            # 2. Count resources per RG via single resources list call
            resource_counts: dict[str, int] = {}
            try:
                resources = list(resource_client.resources.list())
                for r in resources:
                    # Resource IDs contain the RG name: /subscriptions/.../resourceGroups/{rg}/...
                    rid = r.id or ""
                    parts = rid.split("/")
                    try:
                        rg_name = parts[parts.index("resourceGroups") + 1].lower()
                        resource_counts[rg_name] = resource_counts.get(rg_name, 0) + 1
                    except (ValueError, IndexError):
                        pass
            except Exception as resources_err:
                logger.debug(
                    "Listing resources for subscription %s failed: %s", sub_id, resources_err
                )

            for rg in rgs:
                name = rg.name or ""
                provisioning_state = (
                    rg.properties.provisioning_state
                    if rg.properties and getattr(rg.properties, "provisioning_state", None)
                    else ""
                )
                resource_groups.append({
                    "name": name,
                    "location": rg.location or "",
                    "subscription_id": sub_id,
                    "subscription_name": sub_name,
                    "provisioning_state": provisioning_state,
                    "tags": rg.tags or {},
                    "resource_count": resource_counts.get(name.lower(), 0),
                    "id": rg.id or "",
                })

            ctx.info(f"  {sub_name}: {len(rgs)} resource group(s)")

        return {
            "provider": ctx.provider_name,
            "tenant_id": tenant_id,
            "subscription_count": len(enabled_subs),
            "total": len(resource_groups),
            "resource_groups": resource_groups,
        }

    except Exception as e:
        logger.error("Azure enum_resource_groups failed: %s", e)
        return {"error": str(e), "resource_groups": []}
