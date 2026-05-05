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
# PROVIDERS: Entra (ARM REST, same pattern as azure_enum_subscriptions)
#
# HOW IT WORKS:
#   1. Acquires an ARM bearer token from the active EntraTokenStore
#      (direct access token or FOCI expansion).
#   2. Calls GET /subscriptions?api-version=2022-12-01 to discover
#      all accessible subscriptions.
#   3. For each subscription, calls:
#        GET /subscriptions/{sub}/resourcegroups?api-version=2021-04-01
#      to enumerate all resource groups.
#   4. In the same pass, fetches resources per subscription
#        GET /subscriptions/{sub}/resources?api-version=2021-04-01
#      and groups the count by resource group name.
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

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.arm import arm_list
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.token_store import ARM, EntraTokenStore

_SUBSCRIPTIONS_URL = "https://management.azure.com/subscriptions?api-version=2022-12-01"
_RG_URL = "https://management.azure.com/subscriptions/{sub}/resourcegroups?api-version=2021-04-01"
_RESOURCES_URL = "https://management.azure.com/subscriptions/{sub}/resources?api-version=2021-04-01"

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
    providers=["entra"],
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
    """Enumerate Azure resource groups via ARM."""
    store: EntraTokenStore = ctx.session

    token = store.best_token(ARM)
    if token is None:
        return {"error": "No ARM token available. Run: acquire entra arm"}

    if token.token_type == "refresh_token":
        token = foci_expand(store, ARM)
        if token is None:
            return {"error": "FOCI expansion for ARM failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    with httpx.Client(timeout=60) as http:
        subscriptions = arm_list(http, _SUBSCRIPTIONS_URL, headers)
        enabled_subs = [s for s in subscriptions if s.get("state") == "Enabled"]

        ctx.info(f"Enumerating resource groups across {len(enabled_subs)} subscription(s)...")

        resource_groups: list[dict] = []
        for sub in enabled_subs:
            sub_id = sub["subscriptionId"]
            sub_name = sub.get("displayName", sub_id)

            # 1. Enumerate resource groups in this subscription
            rgs = arm_list(http, _RG_URL.format(sub=sub_id), headers)

            # 2. Count resources per RG via single resources list call
            resource_counts: dict[str, int] = {}
            try:
                resources = arm_list(http, _RESOURCES_URL.format(sub=sub_id), headers)
                for r in resources:
                    # Resource IDs contain the RG name: /subscriptions/.../resourceGroups/{rg}/...
                    rid = r.get("id", "")
                    parts = rid.split("/")
                    try:
                        rg_name = parts[parts.index("resourceGroups") + 1].lower()
                        resource_counts[rg_name] = resource_counts.get(rg_name, 0) + 1
                    except (ValueError, IndexError):
                        pass
            except Exception:
                pass

            for rg in rgs:
                name = rg.get("name", "")
                resource_groups.append({
                    "name": name,
                    "location": rg.get("location", ""),
                    "subscription_id": sub_id,
                    "subscription_name": sub_name,
                    "provisioning_state": rg.get("properties", {}).get("provisioningState", ""),
                    "tags": rg.get("tags", {}),
                    "resource_count": resource_counts.get(name.lower(), 0),
                    "id": rg.get("id", ""),
                })

            ctx.info(f"  {sub_name}: {len(rgs)} resource group(s)")

    return {
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "subscription_count": len(enabled_subs),
        "total": len(resource_groups),
        "resource_groups": resource_groups,
    }
