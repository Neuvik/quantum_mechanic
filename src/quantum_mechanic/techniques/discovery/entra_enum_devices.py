# ================================================================
# TECHNIQUE: discovery/entra_enum_devices
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Enumerate Entra ID registered and joined devices.
#            Identifies Azure AD joined, Hybrid joined, and
#            registered devices. Surfaces non-compliant devices
#            that may bypass Conditional Access device controls.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Calls GET /devices with $select for key compliance fields.
#   Classifies by trustType: AzureAD (cloud-joined), ServerAD
#   (hybrid-joined), Workplace (registered only).
#
# DETECTION (Blue Team):
#   Graph Audit Logs: microsoft.graph/devices/read.
#   Alert on: /devices enumeration is a strong indicator that an
#     attacker is mapping the device inventory to plan CAP bypass —
#     specifically looking for non-compliant or non-joined devices
#     that could be used to avoid device-based CAP policies.
#
# SAFE:     Yes — read-only. No state changes.
# ================================================================

from __future__ import annotations

from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    graph_error_to_result,
    graph_list,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, OAUTH_REFRESH, EntraTokenStore

_DEVICES_URL = (
    "https://graph.microsoft.com/v1.0/devices"
    "?$select=id,displayName,operatingSystem,operatingSystemVersion,"
    "trustType,isCompliant,isManaged,registeredDateTime,approximateLastSignInDateTime"
    "&$top=999"
)

# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "devices"
LOOT_SCHEMA = [
    ("displayName", "Device Name", "bold cyan"),
    ("operatingSystem", "OS", "white"),
    ("trustType", "Trust Type", "dim"),
    ("isCompliant", "Compliant", "dim"),
    ("isManaged", "Managed", "dim"),
    ("id", "Object ID", "dim"),
]

_TRUST_TYPE_LABELS = {
    "AzureAD": "Azure AD Joined",
    "ServerAD": "Hybrid Joined",
    "Workplace": "Registered",
}


def _format_entra_enum_devices(result: Any) -> None:
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

    devices = data.get("devices", [])
    total = data.get("total", 0)
    non_compliant = data.get("non_compliant", 0)
    by_trust = data.get("by_trust_type", {})

    console.print(
        f"  [bold green]✓[/bold green] Enumerated [bold]{total}[/bold] devices"
        + (f"  [red]({non_compliant} non-compliant)[/red]" if non_compliant else "")
    )
    for trust, count in sorted(by_trust.items()):
        label = _TRUST_TYPE_LABELS.get(trust, trust)
        console.print(f"    [dim]{label}:[/dim] {count}")

    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("Device Name", style="cyan")
    tbl.add_column("OS", style="dim")
    tbl.add_column("Trust Type", style="dim")
    tbl.add_column("Compliant", style="dim")
    tbl.add_column("Managed", style="dim")

    for d in devices[:100]:
        compliant = d.get("isCompliant")
        compliant_str = (
            "[green]✓[/green]"
            if compliant
            else ("[red]✗[/red]" if compliant is False else "[dim]?[/dim]")
        )
        managed = d.get("isManaged")
        managed_str = "[green]✓[/green]" if managed else "[dim]✗[/dim]"
        trust = d.get("trustType", "—")
        os_ver = d.get("operatingSystem", "—")
        tbl.add_row(d.get("displayName", "—"), os_ver, trust, compliant_str, managed_str)

    console.print(tbl)
    if total > 100:
        console.print(f"  [dim]... and {total - 100} more devices in result data[/dim]")


@technique(
    technique_id="discovery/entra_enum_devices",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="info",
    safe=True,
    description=("Enumerate Entra ID registered and joined devices, including compliance status."),
    formatter=_format_entra_enum_devices,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Entra ID devices via Graph /devices."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == OAUTH_REFRESH:
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    try:
        with httpx.Client(timeout=60) as http:
            devices = graph_list(http, _DEVICES_URL, headers)
    except GraphError as e:
        return graph_error_to_result(e, devices=[], total=0, non_compliant=0, by_trust_type={})

    non_compliant = sum(1 for d in devices if d.get("isCompliant") is False)
    by_trust: dict[str, int] = {}
    copied_devices = []
    for d in devices:
        raw_trust = d.get("trustType") or "Unknown"
        d_copy = dict(d)
        d_copy["trustType"] = _TRUST_TYPE_LABELS.get(raw_trust, raw_trust)
        copied_devices.append(d_copy)
        by_trust[raw_trust] = by_trust.get(raw_trust, 0) + 1

    return {
        "status": "success",
        "provider": "entra",
        "tenant_id": store.tenant_id,
        "total": len(devices),
        "non_compliant": non_compliant,
        "by_trust_type": by_trust,
        "devices": copied_devices,
    }
