# ================================================================
# TECHNIQUE: discovery/entra_enum_ca_policy
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Fetch and render a single Conditional Access policy in
#            full detail. Complements the aggregated view produced
#            by entra_enum_conditional_access_policies, which
#            summarizes counts per policy — this technique shows
#            the entire conditions/grantControls/sessionControls
#            structure so operators can reason about exclusions
#            without opening the portal.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Accepts --name <policy-name> OR --id <policy-id>. When --id is
#   provided we call /identity/conditionalAccess/policies/{id}
#   directly. When --name is provided we list all policies and
#   match on displayName (case-insensitive substring).
#
# DETECTION (Blue Team):
#   Graph Audit Logs:
#     microsoft.graph/identity/conditionalAccess/policies/read
#   Volume is low (single policy fetch) so this is unlikely to
#   trigger blue-team enumeration alarms.
#
# OPSEC:     LOW — Single Graph GET.
# SAFE:      Yes — read-only.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, ParameterType, technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    graph_error_to_result,
    graph_list,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)

_POLICIES_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"


def _format_ca_policy(result: Any) -> None:
    from rich import box
    from rich.panel import Panel
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

    policy = data.get("policy", {})
    name = policy.get("displayName", "unknown")
    state = policy.get("state", "unknown")
    console.print(
        f"  [bold green]✓[/bold green] [bold]{name}[/bold]  "
        f"[dim]state:[/dim] [bold]{state}[/bold]"
    )
    console.print(
        "  [dim]Exclusion semantics: a subject is exempted if ANY single "
        "exclusion category matches — user OR group OR role OR location OR app.[/dim]"
    )

    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}

    def _section(title: str, items: list[str]) -> None:
        if not items:
            return
        tbl = Table(box=box.ROUNDED, title=title, border_style="dim", show_header=False)
        for it in items:
            tbl.add_row(str(it))
        console.print(tbl)

    _section("Include Users", users.get("includeUsers") or [])
    _section("Exclude Users", users.get("excludeUsers") or [])
    _section("Include Groups", users.get("includeGroups") or [])
    _section("Exclude Groups", users.get("excludeGroups") or [])
    _section("Include Roles", users.get("includeRoles") or [])
    _section("Exclude Roles", users.get("excludeRoles") or [])

    apps = conditions.get("applications") or {}
    _section("Include Applications", apps.get("includeApplications") or [])
    _section("Exclude Applications", apps.get("excludeApplications") or [])

    locs = conditions.get("locations") or {}
    _section("Include Locations", locs.get("includeLocations") or [])
    _section("Exclude Locations", locs.get("excludeLocations") or [])

    grant = policy.get("grantControls") or {}
    if grant:
        console.print(Panel(
            f"Operator: [bold]{grant.get('operator', '—')}[/bold]\n"
            f"Built-in controls: {', '.join(grant.get('builtInControls') or []) or 'None'}\n"
            f"Custom auth strengths: {(grant.get('authenticationStrength') or {}).get('displayName') or 'None'}",
            title="Grant Controls",
            border_style="green",
        ))

    session = policy.get("sessionControls") or {}
    if session:
        entries = [f"{k}: {v}" for k, v in session.items() if v]
        if entries:
            console.print(Panel(
                "\n".join(entries),
                title="Session Controls",
                border_style="cyan",
            ))


@technique(
    technique_id="discovery/entra_enum_ca_policy",
    tactic="discovery",
    mitre_id="T1580",
    providers=["entra"],
    severity="info",
    safe=True,
    description=(
        "Fetch a single Conditional Access policy by name or id and render it "
        "in full detail (conditions, exclusions, grant, session controls)."
    ),
    formatter=_format_ca_policy,
    parameters=[
        Parameter(
            "id",
            "Object ID of the CA policy to fetch.",
            required=False,
            type=ParameterType.STRING,
        ),
        Parameter(
            "name",
            "Display name (case-insensitive substring) of the CA policy to fetch.",
            required=False,
            type=ParameterType.STRING,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Fetch a single CA policy by id or name."""
    policy_id = ctx.get_param("id")
    name_query = ctx.get_param("name")

    if not policy_id and not name_query:
        return {
            "status": "error",
            "error": "Either --id or --name is required.",
        }

    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"status": "error", "error": "No Graph token available."}
    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"status": "error", "error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}

    with httpx.Client(timeout=30) as http:
        if policy_id:
            url = f"{_POLICIES_URL}/{policy_id}"
            try:
                resp = http.get(url, headers=headers)
            except Exception as exc:
                return {"status": "error", "error": f"Graph GET failed: {exc}"}
            if resp.status_code == 404:
                return {
                    "status": "error",
                    "error": f"CA policy {policy_id!r} not found.",
                }
            if resp.status_code != 200:
                return {
                    "status": "denied" if 400 <= resp.status_code < 500 else "error",
                    "error": f"HTTP {resp.status_code} fetching CA policy",
                    "required_scope": "Policy.Read.ConditionalAccess",
                }
            return {"status": "success", "policy": resp.json()}

        # Name query: list all and match on displayName.
        try:
            policies = graph_list(http, _POLICIES_URL, headers)
        except GraphError as e:
            return graph_error_to_result(e, policy={})

        needle = name_query.lower()
        matches = [
            p for p in policies
            if needle in (p.get("displayName") or "").lower()
        ]
        if not matches:
            return {
                "status": "error",
                "error": f"No CA policy matches name substring {name_query!r}",
            }
        if len(matches) > 1:
            names = [p.get("displayName") for p in matches]
            return {
                "status": "error",
                "error": (
                    f"Name substring {name_query!r} matches {len(matches)} policies: "
                    f"{names}. Use --id for exact match."
                ),
            }
        return {"status": "success", "policy": matches[0]}
