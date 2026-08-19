# ================================================================
# TECHNIQUE: discovery/entra_enum_conditional_access_policies
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Enumerate all Conditional Access policies in the tenant.
#            This reveals authentication requirements (MFA, devices)
#            and exclusions (users, groups, roles, apps, platforms,
#            locations) that may allow bypassing security controls.
#
# PROVIDERS: Entra
#
# OPSEC:     LOW — Standard Graph API queries.
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import (
    GraphError,
    _graph_call,
    graph_error_to_result,
    graph_list,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

if TYPE_CHECKING:
    from quantum_mechanic.core.workspace import Workspace

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Static Built-in Entra ID Role Template IDs
# ----------------------------------------------------------------
BUILTIN_ENTRA_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "29232cdf-58b0-46b5-83fd-111e64983981": "Security Administrator",
    "3b395060-a13f-4206-ac6b-952de5cd5983": "Security Reader",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "e6d1a158-b705-4acb-934d-df2a8c2483a9": "Application Administrator",
    "f287042a-a92c-47c0-84f1-689e4726b27e": "Cloud Application Administrator",
    "2af84b1e-32c8-42b7-82bc-9d87d445707f": "Conditional Access Administrator",
    "c4e3fbe3-59c3-4f7f-bb8e-1768686e0c27": "Exchange Administrator",
    "69080b06-4444-469a-9e0a-0498a444d320": "SharePoint Administrator",
    "9670f948-4e5c-4da6-9012-b4ee6ea699b8": "Teams Administrator",
    "194a224a-aa2c-49fb-863d-b40f295b9c28": "Compliance Administrator",
    "b0f54661-2d74-4c50-afa3-1ec88cabe910": "Directory Readers",
    "88d8e3e2-8d19-45ad-9588-4449832d2479": "Directory Writers",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "3a2c56b5-1153-4886-b4d4-b77871e847c2": "Billing Administrator",
    "1165ca05-2b4b-4b82-9993-978bfd94d784": "Privileged Role Administrator",
    "e8611ab9-8c65-4f3b-90f7-53cfd19c362d": "Global Reader",
    "9b895d31-2c0e-44d8-93c7-d72e6ecf2477": "Cloud Device Administrator",
}

# ----------------------------------------------------------------
# Well-Known Microsoft Application IDs
# ----------------------------------------------------------------
WELL_KNOWN_APPS = {
    "00000002-0000-0000-c000-000000000000": "Windows Azure Active Directory (Microsoft Graph)",
    "00000003-0000-0000-c000-000000000000": "Office 365 Exchange Online / SharePoint",
    "412878b2-6c1e-450a-b924-4ab0924773c3": "Windows Azure Service Management API",
    "797f3497-b840-4c7f-9a74-f901c01f7efb": "Azure Portal / Management",
    "00000009-0000-0000-c000-000000000000": "PowerBI",
    "0000000c-0000-0000-c000-000000000000": "Microsoft App Access Panel",
    "00000005-0000-0000-c000-000000000000": "Yammer",
    "270293b9-db07-42b3-9f17-f6558b3014fc": "Microsoft Teams",
    "Office365": "Office 365",
}

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "policies"
LOOT_SCHEMA = [
    ("display_name", "Policy Name", "bold cyan"),
    ("state", "State", "bold white"),
    ("grant_operator", "Grant Op", "dim"),
    ("grant_controls", "Access Controls", "bold yellow"),
    ("included_users", "Incl Users", "dim"),
    ("excluded_users", "Excl Users", "bold red"),
    ("include_guest_types", "Incl Guests", "dim"),
    ("exclude_guest_types", "Excl Guests", "bold red"),
    ("included_groups", "Incl Groups", "dim"),
    ("excluded_groups", "Excl Groups", "bold red"),
    ("included_roles", "Incl Roles", "dim"),
    ("excluded_roles", "Excl Roles", "bold red"),
    ("included_apps", "Incl Apps", "dim"),
    ("excluded_apps", "Excl Apps", "bold red"),
    ("include_user_actions", "Incl Actions", "dim"),
    ("include_auth_context", "Incl AuthCtx", "dim"),
    ("included_platforms", "Incl Platforms", "dim"),
    ("exclude_platforms", "Excl Platforms", "bold red"),
    ("included_locations", "Incl Locations", "dim"),
    ("excluded_locations", "Excl Locations", "bold red"),
    ("client_app_types", "Client Apps", "dim"),
    ("sign_in_risk_levels", "Sign-in Risk", "dim"),
    ("user_risk_levels", "User Risk", "dim"),
    ("sp_risk_levels", "SP Risk", "dim"),
    ("insider_risk_levels", "Insider Risk", "dim"),
    ("auth_flows", "Auth Flows", "dim"),
    ("device_filter_mode", "Device Filter Mode", "dim"),
    ("device_filter_rule", "Device Filter Rule", "dim"),
    ("session_sign_in_freq", "Session SIF", "dim"),
    ("session_persistent_browser", "Session PB", "dim"),
    ("session_token_protection", "Session TP", "dim"),
    ("session_casb", "Session CASB", "dim"),
    ("id", "Policy ID", "dim"),
]


def get_list(val: Any) -> list[str]:
    """Coerce a value (list or comma-separated string) into a list of strings.

    NOTE: When the caller has a policy dict, prefer `get_list_from_policy()`
    which reads the structured `_list` field so entries with embedded commas
    (e.g. named locations with CIDR lists) survive intact.
    """
    if not val:
        return []
    if isinstance(val, list):
        return [str(x) for x in val if x]
    if isinstance(val, str):
        return [x.strip() for x in val.split(",") if x.strip() and x.strip() != "None"]
    return []


def get_list_from_policy(policy: dict, key: str) -> list[str]:
    """Structured accessor: prefer `<key>_list` if present, fall back to
    `get_list(policy[key])`. This is the CIDR-comma-safe path.
    """
    struct_key = f"{key}_list"
    if isinstance(policy.get(struct_key), list):
        return [str(x) for x in policy[struct_key] if x]
    return get_list(policy.get(key))


def format_conditional_access_policies_result(result: Any) -> None:
    """Formatter for Entra CA Policy enumeration results."""
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    status = data.get("status", "success" if "error" not in data else "error")
    if status in ("denied", "error"):
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        if data.get("required_scope"):
            console.print(f"    [dim]Required scope: {data['required_scope']}[/dim]")
        return
    policies = data.get("policies", [])

    if not policies:
        console.print("  [dim]No Conditional Access policies found.[/dim]")
        return

    glyph = "[bold yellow]⚠[/bold yellow]" if status == "partial" else "[bold green]✓[/bold green]"
    console.print(f"  {glyph} Discovered [bold cyan]{len(policies)}[/bold cyan] CA policy/policies")
    if status == "partial":
        resolution = data.get("resolution") or {}
        unresolved_count = resolution.get("unresolved_count", 0)
        if unresolved_count:
            console.print(
                "    [yellow]Object resolution incomplete[/yellow]"
                f" — [bold]{unresolved_count}[/bold] referenced ID(s) remain unresolved."
            )
        if resolution.get("fallback_skipped_due_to_budget"):
            console.print(
                "    [dim]Large unresolved set detected. QM skipped expensive per-ID Graph fallback "
                "to avoid throttling and returned raw IDs where necessary.[/dim]"
            )
        if resolution.get("throttling_observed"):
            console.print(
                "    [dim]Graph throttling was observed during identity enrichment. "
                "Policy coverage is real; name enrichment is partial.[/dim]"
            )
    # OR-across-categories semantics banner. A user is exempted from a CA
    # policy if ANY single exclusion category matches — this is the
    # attacker-useful mental model that isn't obvious from the raw JSON.
    console.print(
        "  [dim]Exclusion semantics: a subject is exempted if ANY single "
        "exclusion category matches — user OR group OR role OR location OR app.[/dim]"
    )
    console.print(
        "  [dim]Use `run discovery/entra_enum_ca_policy --name <policy>` or "
        "`--id <id>` for full per-policy detail.[/dim]"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Policy Name", style="bold cyan")
    tbl.add_column("State", style="bold white")
    tbl.add_column("Grant Controls", style="bold yellow")
    tbl.add_column("Inclusions", style="dim")
    tbl.add_column("Exclusions (High Value)", style="bold red")

    for p in tbl_data(policies):
        state_style = "green" if p.get("state") == "enabled" else "dim"
        controls = ", ".join(p.get("grant_controls", [])) or "None"

        # Summarize scope
        incls = []
        if p.get("included_users"):
            incls.append(f"Users: {p['included_users']}")
        if p.get("included_groups") and p["included_groups"] != "0":
            incls.append(f"Grps: {p['included_groups']}")
        if p.get("included_roles") and p["included_roles"] != "None":
            incls.append(f"Roles: {p['included_roles']}")
        if p.get("included_apps") and p["included_apps"] != "0":
            incls.append(f"Apps: {p['included_apps']}")
        incls_str = " | ".join(incls)

        excls = []
        if p.get("excluded_users") and p["excluded_users"] != "None":
            excls.append(f"Users: {p['excluded_users']}")
        if p.get("excluded_groups") and p["excluded_groups"] != "None":
            excls.append(f"Grps: {p['excluded_groups']}")
        if p.get("excluded_roles") and p["excluded_roles"] != "None":
            excls.append(f"Roles: {p['excluded_roles']}")
        if p.get("excluded_apps") and p["excluded_apps"] != "None":
            excls.append(f"Apps: {p['excluded_apps']}")
        if p.get("exclude_platforms") and p["exclude_platforms"] != "None":
            excls.append(f"Platforms: {p['exclude_platforms']}")
        if p.get("excluded_locations") and p["excluded_locations"] != "None":
            excls.append(f"Locations: {p['excluded_locations']}")
        excls_str = " | ".join(excls) or "None"

        tbl.add_row(
            p.get("display_name", "Untitled"),
            f"[{state_style}]{p.get('state', 'unknown')}[/{state_style}]",
            controls,
            incls_str,
            excls_str,
        )

    console.print(tbl)

    # Print Bypass Guidance
    bypass_tips = []
    for p in policies:
        name = p.get("display_name", "Untitled")
        state = p.get("state", "unknown")
        controls = ", ".join(get_list(p.get("grant_controls"))) or "None"

        if state == "disabled":
            bypass_tips.append(
                f"  • [bold yellow]Disabled Policy:[/bold yellow] Policy [cyan]'{name}'[/cyan] is disabled. Controls ({controls}) are not active."
            )
        elif "report" in state.lower():
            bypass_tips.append(
                f"  • [bold yellow]Report-Only Mode:[/bold yellow] Policy [cyan]'{name}'[/cyan] is in report-only mode. Controls ({controls}) are logged but not actively enforced."
            )

        ex_users = get_list(p.get("excluded_users"))
        for u in ex_users:
            bypass_tips.append(
                f"  • [bold red]Excluded User:[/bold red] User [white]'{u}'[/white] is excluded from [cyan]'{name}'[/cyan]. Authenticating as this user bypasses controls ({controls})."
            )

        ex_groups = get_list(p.get("excluded_groups"))
        for g in ex_groups:
            bypass_tips.append(
                f"  • [bold red]Excluded Group:[/bold red] Group [white]'{g}'[/white] is excluded from [cyan]'{name}'[/cyan]. Members bypass controls ({controls}). Target group members or add compromised users to this group."
            )

        ex_roles = get_list(p.get("excluded_roles"))
        for r in ex_roles:
            bypass_tips.append(
                f"  • [bold red]Excluded Role:[/bold red] Role [white]'{r}'[/white] is excluded from [cyan]'{name}'[/cyan]. Members bypass controls ({controls})."
            )

        ex_apps = get_list(p.get("excluded_apps"))
        for a in ex_apps:
            bypass_tips.append(
                f"  • [bold red]Excluded App:[/bold red] Application [white]'{a}'[/white] is excluded from [cyan]'{name}'[/cyan]. Access via this app bypasses controls ({controls})."
            )

        ex_platforms = get_list(p.get("exclude_platforms"))
        for pl in ex_platforms:
            bypass_tips.append(
                f"  • [bold red]Excluded Platform:[/bold red] Platform [white]'{pl}'[/white] is excluded from [cyan]'{name}'[/cyan]. Spoofing User-Agent bypasses controls ({controls})."
            )

        ex_locations = get_list_from_policy(p, "excluded_locations")
        for loc in ex_locations:
            bypass_tips.append(
                f"  • [bold red]Excluded Location:[/bold red] Location [white]'{loc}'[/white] is excluded from [cyan]'{name}'[/cyan]. Access from this network bypasses controls ({controls})."
            )

        client_apps = [x.lower() for x in get_list(p.get("client_app_types"))]
        if "exchangeactivesync" in client_apps or "other" in client_apps:
            legacy = [c for c in client_apps if c in ["exchangeactivesync", "other"]]
            bypass_tips.append(
                f"  • [bold yellow]Legacy Auth Allowed:[/bold yellow] Legacy authentication ({', '.join(legacy)}) allowed in [cyan]'{name}'[/cyan]. Bypasses modern MFA controls."
            )

    if bypass_tips:
        console.print("\n  [bold yellow]Bypass & Penetration Testing Guidance:[/bold yellow]")
        for tip in bypass_tips:
            console.print(tip)


def tbl_data(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Helper to transform parsed policies for the table view."""
    rows = []
    for p in policies:
        # User inclusions/exclusions
        inc_u = get_list(p.get("included_users"))
        exc_u = get_list(p.get("excluded_users"))
        incl_users = "All" if "All" in inc_u else (f"{len(inc_u)} users" if inc_u else "")
        excl_users = ", ".join(exc_u) if exc_u else "None"

        # Group inclusions/exclusions
        inc_g = get_list(p.get("included_groups"))
        exc_g = get_list(p.get("excluded_groups"))
        incl_groups = f"{len(inc_g)}" if inc_g else "0"
        excl_groups = ", ".join(exc_g) if exc_g else "None"

        # Role inclusions/exclusions
        inc_r = get_list(p.get("included_roles"))
        exc_r = get_list(p.get("excluded_roles"))
        incl_roles = ", ".join(inc_r) if inc_r else "None"
        excl_roles = ", ".join(exc_r) if exc_r else "None"

        # App inclusions/exclusions
        inc_a = get_list(p.get("included_apps"))
        exc_a = get_list(p.get("excluded_apps"))
        incl_apps = "All" if "All" in inc_a else (f"{len(inc_a)}" if inc_a else "0")
        excl_apps = ", ".join(exc_a) if exc_a else "None"

        # Platform inclusions/exclusions
        inc_pl = get_list(p.get("included_platforms"))
        exc_pl = get_list(p.get("exclude_platforms"))
        incl_platforms = ", ".join(inc_pl) if inc_pl else "All"
        excl_platforms = ", ".join(exc_pl) if exc_pl else "None"

        # Location inclusions/exclusions
        inc_loc = get_list_from_policy(p, "included_locations")
        exc_loc = get_list_from_policy(p, "excluded_locations")
        incl_locations = ", ".join(inc_loc) if inc_loc else "All"
        excl_locations = ", ".join(exc_loc) if exc_loc else "None"

        # Client app types
        client_apps = get_list(p.get("client_app_types"))
        client_apps_str = ", ".join(client_apps) if client_apps else "All"

        rows.append(
            {
                "display_name": p.get("display_name"),
                "state": p.get("state"),
                "grant_controls": get_list(p.get("grant_controls")),
                "included_users": incl_users,
                "excluded_users": excl_users,
                "included_groups": incl_groups,
                "excluded_groups": excl_groups,
                "included_roles": incl_roles,
                "excluded_roles": excl_roles,
                "included_apps": incl_apps,
                "excluded_apps": excl_apps,
                "included_platforms": incl_platforms,
                "exclude_platforms": excl_platforms,
                "included_locations": incl_locations,
                "excluded_locations": excl_locations,
                "client_app_types": client_apps_str,
                "id": p.get("id"),
                # Ensure the extra fields exist in row dict too
                "grant_operator": p.get("grant_operator", "OR"),
                "include_guest_types": p.get("include_guest_types", ""),
                "exclude_guest_types": p.get("exclude_guest_types", ""),
                "include_user_actions": p.get("include_user_actions", "None"),
                "include_auth_context": p.get("include_auth_context", "None"),
                "sign_in_risk_levels": p.get("sign_in_risk_levels", "None"),
                "user_risk_levels": p.get("user_risk_levels", "None"),
                "sp_risk_levels": p.get("sp_risk_levels", "None"),
                "insider_risk_levels": p.get("insider_risk_levels", ""),
                "auth_flows": p.get("auth_flows", ""),
                "device_filter_mode": p.get("device_filter_mode", ""),
                "device_filter_rule": p.get("device_filter_rule", ""),
                "session_sign_in_freq": p.get("session_sign_in_freq", ""),
                "session_persistent_browser": p.get("session_persistent_browser", ""),
                "session_token_protection": p.get("session_token_protection", ""),
                "session_casb": p.get("session_casb", ""),
            }
        )
    return rows


def load_loot_mappings(workspace_db_path: Path | Workspace | None) -> dict[str, str]:
    """Parse local users/groups/apps loot and database evidence to resolve IDs to names."""
    mapping = {}
    if not workspace_db_path:
        return mapping

    from quantum_mechanic.core.workspace import Workspace

    is_workspace = isinstance(workspace_db_path, Workspace)
    db_path = workspace_db_path.db_path if is_workspace else workspace_db_path

    def add_to_mapping(key: str, val: str):
        if not key or not val:
            return
        key_str = str(key).strip()
        val_str = str(val).strip()
        mapping[key_str] = val_str
        mapping[key_str.lower()] = val_str

    def _norm_dict(d: dict) -> dict[str, Any]:
        return {
            str(k).lower().replace(" ", "").replace("_", ""): v
            for k, v in d.items()
            if k is not None
        }

    # 1. Primary: query database evidence table and principals table
    evidence_rows = []
    if is_workspace:
        try:
            # First, pull direct principal listings
            for p in workspace_db_path.list_principals():
                if p.id and p.friendly_name:
                    add_to_mapping(p.id, p.friendly_name)
        except Exception as p_ex:
            logger.debug("Failed to list principals from workspace: %s", p_ex)

        try:
            target_techs = {
                "discovery/entra_enum_users",
                "discovery/unified_enum_users",
                "discovery/entra_enum_groups",
                "discovery/unified_enum_groups",
                "discovery/entra_enum_apps",
                "discovery/unified_enum_apps",
                "discovery/entra_enum_group_members",
                "discovery/entra_enum_privileged_roles",
                "discovery/whoami",
                "discovery/entra_whoami",
                "discovery/entra_enum_identity",
                "discovery/entra_enum_self",
                "discovery/entra_enum_devices",
            }
            evidence_rows = [
                row
                for row in workspace_db_path.list_evidence()
                if row.get("technique_id") in target_techs
            ]
        except Exception as ev_ex:
            logger.debug("Failed to list evidence from workspace: %s", ev_ex)
    else:
        try:
            import sqlite3

            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query principals table
            try:
                cursor.execute("SELECT id, friendly_name FROM principals")
                p_rows = cursor.fetchall()
                for p_row in p_rows:
                    if p_row["id"] and p_row["friendly_name"]:
                        add_to_mapping(p_row["id"], p_row["friendly_name"])
            except Exception as p_ex:
                logger.debug("Failed to query principals table in sqlite fallback: %s", p_ex)

            # Query evidence table
            cursor.execute(
                """
                SELECT technique_id, output_json 
                FROM evidence 
                WHERE technique_id IN (
                    'discovery/entra_enum_users', 
                    'discovery/unified_enum_users', 
                    'discovery/entra_enum_groups', 
                    'discovery/unified_enum_groups',
                    'discovery/entra_enum_apps',
                    'discovery/unified_enum_apps',
                    'discovery/entra_enum_group_members',
                    'discovery/entra_enum_privileged_roles',
                    'discovery/whoami',
                    'discovery/entra_whoami',
                    'discovery/entra_enum_identity',
                    'discovery/entra_enum_self',
                    'discovery/entra_enum_devices'
                )
                ORDER BY id ASC
                """
            )
            evidence_rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
        except Exception as db_ex:
            logger.debug("Failed to query database for resolution mappings: %s", db_ex)

    for row in evidence_rows:
        tech_id = row["technique_id"]
        try:
            data = json.loads(row["output_json"])
            if not isinstance(data, dict):
                continue
            if tech_id in ("discovery/entra_enum_users", "discovery/unified_enum_users"):
                users_list = data.get("users") or []
                for u in users_list:
                    if not isinstance(u, dict):
                        continue
                    u_norm = _norm_dict(u)
                    uid = u_norm.get("id") or u_norm.get("userid") or u_norm.get("objectid")
                    upn = (
                        u_norm.get("userprincipalname")
                        or u_norm.get("username")
                        or u_norm.get("name")
                        or u_norm.get("upn")
                    )
                    if uid and upn:
                        add_to_mapping(uid, upn)
            elif tech_id in ("discovery/entra_enum_groups", "discovery/unified_enum_groups"):
                groups_list = data.get("groups") or []
                for g in groups_list:
                    if not isinstance(g, dict):
                        continue
                    g_norm = _norm_dict(g)
                    gid = g_norm.get("id") or g_norm.get("groupid") or g_norm.get("objectid")
                    disp = (
                        g_norm.get("displayname") or g_norm.get("groupname") or g_norm.get("name")
                    )
                    if gid and disp:
                        add_to_mapping(gid, disp)
            elif tech_id in ("discovery/entra_enum_apps", "discovery/unified_enum_apps"):
                apps_list = (
                    data.get("apps")
                    or data.get("applications")
                    or data.get("service_principals")
                    or []
                )
                for a in apps_list:
                    if not isinstance(a, dict):
                        continue
                    a_norm = _norm_dict(a)
                    aid = a_norm.get("id") or a_norm.get("objectid")
                    appid = a_norm.get("appid")
                    disp = a_norm.get("displayname") or a_norm.get("name")
                    if disp:
                        if aid:
                            add_to_mapping(aid, disp)
                        if appid:
                            add_to_mapping(appid, disp)
            elif tech_id == "discovery/entra_enum_group_members":
                members_list = data.get("members") or []
                for m in members_list:
                    if not isinstance(m, dict):
                        continue
                    m_norm = _norm_dict(m)
                    gid = m_norm.get("groupid")
                    gname = m_norm.get("groupname")
                    mid = m_norm.get("memberid")
                    mname = m_norm.get("membername")
                    if gid and gname:
                        add_to_mapping(gid, gname)
                    if mid and mname:
                        add_to_mapping(mid, mname)
            elif tech_id == "discovery/entra_enum_privileged_roles":
                assignments_list = data.get("assignments") or []
                for a in assignments_list:
                    if not isinstance(a, dict):
                        continue
                    a_norm = _norm_dict(a)
                    pid = a_norm.get("principalid")
                    pname = a_norm.get("principalname")
                    if pid and pname:
                        add_to_mapping(pid, pname)
            elif tech_id in ("discovery/whoami", "discovery/entra_whoami"):
                pid = data.get("principal_id")
                me_dict = data.get("me")
                upn = None
                if isinstance(me_dict, dict):
                    upn = (
                        me_dict.get("userPrincipalName")
                        or me_dict.get("mail")
                        or me_dict.get("displayName")
                    )
                if not upn:
                    upn = data.get("friendly_name")
                if pid and upn:
                    add_to_mapping(pid, upn)
                g_list = data.get("groups") or []
                for g in g_list:
                    if isinstance(g, dict):
                        gid = g.get("id")
                        gname = g.get("displayName")
                        if gid and gname:
                            add_to_mapping(gid, gname)
                dr_list = data.get("directory_roles") or []
                for dr in dr_list:
                    if isinstance(dr, dict):
                        drid = dr.get("id")
                        drtemplate = dr.get("roleTemplateId")
                        drname = dr.get("displayName")
                        if drname:
                            if drid:
                                add_to_mapping(drid, drname)
                            if drtemplate:
                                add_to_mapping(drtemplate, drname)
            elif tech_id == "discovery/entra_enum_identity":
                pid = data.get("principal_id")
                me_dict = data.get("me")
                upn = None
                if isinstance(me_dict, dict):
                    upn = (
                        me_dict.get("userPrincipalName")
                        or me_dict.get("mail")
                        or me_dict.get("displayName")
                    )
                if pid and upn:
                    add_to_mapping(pid, upn)
                g_list = data.get("groups") or []
                for g in g_list:
                    if isinstance(g, dict):
                        gid = g.get("id")
                        gname = g.get("displayName")
                        if gid and gname:
                            add_to_mapping(gid, gname)
                dr_list = data.get("directory_roles") or []
                for dr in dr_list:
                    if isinstance(dr, dict):
                        drid = dr.get("id")
                        drtemplate = dr.get("roleTemplateId")
                        drname = dr.get("displayName")
                        if drname:
                            if drid:
                                add_to_mapping(drid, drname)
                            if drtemplate:
                                add_to_mapping(drtemplate, drname)
            elif tech_id == "discovery/entra_enum_self":
                user_dict = data.get("user")
                if isinstance(user_dict, dict):
                    uid = user_dict.get("id")
                    upn = user_dict.get("userPrincipalName") or user_dict.get("displayName")
                    if uid and upn:
                        add_to_mapping(uid, upn)
                g_list = data.get("groups") or []
                for g in g_list:
                    if isinstance(g, dict):
                        gid = g.get("id")
                        gname = g.get("displayName")
                        if gid and gname:
                            add_to_mapping(gid, gname)
                r_list = data.get("roles") or []
                for r in r_list:
                    if isinstance(r, dict):
                        rid = r.get("id")
                        rname = r.get("displayName")
                        if rid and rname:
                            add_to_mapping(rid, rname)
            elif tech_id == "discovery/entra_enum_devices":
                devices_list = data.get("devices") or []
                for d in devices_list:
                    if not isinstance(d, dict):
                        continue
                    d_norm = _norm_dict(d)
                    did = d_norm.get("id")
                    dname = d_norm.get("displayname")
                    if did and dname:
                        add_to_mapping(did, dname)
        except Exception as inner_ex:
            logger.debug("Failed to parse output_json for %s: %s", tech_id, inner_ex)

    # 2. Fallback: load from local CSV loot files
    try:
        loot_dir = db_path.parent / db_path.stem / "loot"

        # Load from all potential user CSVs
        for sub in ["entra_enum_users", "unified_enum_users"]:
            users_csv = loot_dir / "discovery" / sub / "loot.csv"
            if users_csv.exists():
                try:
                    with users_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            uid = r_norm.get("id") or r_norm.get("userid") or r_norm.get("objectid")
                            upn = (
                                r_norm.get("userprincipalname")
                                or r_norm.get("username")
                                or r_norm.get("name")
                                or r_norm.get("upn")
                            )
                            if uid and upn:
                                add_to_mapping(uid, upn)
                except Exception as csv_err:
                    logger.debug("Failed to load user CSV map from %s: %s", sub, csv_err)

        # Load from all potential group CSVs
        for sub in ["entra_enum_groups", "unified_enum_groups"]:
            groups_csv = loot_dir / "discovery" / sub / "loot.csv"
            if groups_csv.exists():
                try:
                    with groups_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            gid = (
                                r_norm.get("id") or r_norm.get("groupid") or r_norm.get("objectid")
                            )
                            disp = (
                                r_norm.get("displayname")
                                or r_norm.get("groupname")
                                or r_norm.get("name")
                            )
                            if gid and disp:
                                add_to_mapping(gid, disp)
                except Exception as csv_err:
                    logger.debug("Failed to load group CSV map from %s: %s", sub, csv_err)

        # Load from all potential app CSVs
        for sub in ["entra_enum_apps", "unified_enum_apps"]:
            apps_csv = loot_dir / "discovery" / sub / "loot.csv"
            if apps_csv.exists():
                try:
                    with apps_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            aid = r_norm.get("id") or r_norm.get("objectid")
                            appid = r_norm.get("appid")
                            disp = r_norm.get("displayname") or r_norm.get("name")
                            if disp:
                                if aid:
                                    add_to_mapping(aid, disp)
                                if appid:
                                    add_to_mapping(appid, disp)
                except Exception as csv_err:
                    logger.debug("Failed to load app CSV map from %s: %s", sub, csv_err)

        # Load from group members CSVs
        for sub in ["entra_enum_group_members"]:
            members_csv = loot_dir / "discovery" / sub / "loot.csv"
            if members_csv.exists():
                try:
                    with members_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            gid = r_norm.get("groupid")
                            gname = r_norm.get("groupname")
                            mid = r_norm.get("memberid")
                            mname = r_norm.get("membername")
                            if gid and gname:
                                add_to_mapping(gid, gname)
                            if mid and mname:
                                add_to_mapping(mid, mname)
                except Exception as csv_err:
                    logger.debug("Failed to load group members CSV map from %s: %s", sub, csv_err)

        # Load from privileged roles CSVs
        for sub in ["entra_enum_privileged_roles"]:
            roles_csv = loot_dir / "discovery" / sub / "loot.csv"
            if roles_csv.exists():
                try:
                    with roles_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            pid = r_norm.get("principalid")
                            pname = r_norm.get("principalname")
                            if pid and pname:
                                add_to_mapping(pid, pname)
                except Exception as csv_err:
                    logger.debug(
                        "Failed to load privileged roles CSV map from %s: %s", sub, csv_err
                    )

        # Load from roles CSVs
        for sub in ["entra_enum_privileged_roles"]:
            roles_csv = loot_dir / "discovery" / sub / "loot.csv"
            if roles_csv.exists():
                try:
                    with roles_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            rid = r_norm.get("roleid")
                            rname = r_norm.get("rolename")
                            pid = r_norm.get("principalid")
                            pname = r_norm.get("principalname")
                            if rid and rname:
                                add_to_mapping(rid, rname)
                            if pid and pname:
                                add_to_mapping(pid, pname)
                except Exception as csv_err:
                    logger.debug("Failed to load roles CSV map from %s: %s", sub, csv_err)

        # Load from devices CSVs
        for sub in ["entra_enum_devices"]:
            devices_csv = loot_dir / "discovery" / sub / "loot.csv"
            if devices_csv.exists():
                try:
                    with devices_csv.open(newline="", encoding="utf-8") as fh:
                        reader = csv.DictReader(fh)
                        for r in reader:
                            r_norm = _norm_dict(r)
                            did = r_norm.get("id") or r_norm.get("objectid")
                            dname = r_norm.get("displayname") or r_norm.get("name")
                            if did and dname:
                                add_to_mapping(did, dname)
                except Exception as csv_err:
                    logger.debug("Failed to load devices CSV map from %s: %s", sub, csv_err)
    except Exception as path_ex:
        logger.debug("Failed to process local loot folder fallback: %s", path_ex)
    except Exception as path_ex:
        logger.debug("Failed to process local loot folder fallback: %s", path_ex)

    return mapping


def _resolve_directory_objects_with_diagnostics(
    http: httpx.Client,
    headers: dict[str, str],
    ids: list[str],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Resolve directory object IDs and report whether enrichment was degraded."""
    if not ids:
        return {}, {
            "attempted": 0,
            "resolved_count": 0,
            "unresolved_count": 0,
            "fallback_skipped_due_to_budget": False,
            "throttling_observed": False,
            "sample_unresolved_ids": [],
        }

    import re

    # Match standard GUID or typical test mock IDs (e.g. guid-1, mock-user)
    uuid_pattern = re.compile(
        r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(guid|mock|test)-\w+)$",
        re.IGNORECASE,
    )
    valid_ids = [x for x in ids if x and uuid_pattern.match(str(x))]

    if not valid_ids:
        return {}, {
            "attempted": 0,
            "resolved_count": 0,
            "unresolved_count": 0,
            "fallback_skipped_due_to_budget": False,
            "throttling_observed": False,
            "sample_unresolved_ids": [],
        }

    resolved = {}
    throttling_observed = False
    chunk_size = 900
    for i in range(0, len(valid_ids), chunk_size):
        chunk = valid_ids[i : i + chunk_size]
        url = "https://graph.microsoft.com/v1.0/directoryObjects/getByIds"
        body = {
            "ids": chunk,
            "types": ["user", "group", "directoryRole", "servicePrincipal", "device"],
        }
        try:
            resp = _graph_call(http, "POST", url, headers=headers, json_data=body)
            if resp.status_code == 200:
                data = resp.json()
                for obj in data.get("value", []):
                    obj_id = obj.get("id")
                    if not obj_id:
                        continue
                    name = obj.get("userPrincipalName") or obj.get("displayName") or obj_id
                    resolved[obj_id] = name
            else:
                if resp.status_code == 429:
                    throttling_observed = True
                logger.debug("getByIds returned status code %d: %s", resp.status_code, resp.text)
        except Exception as e:
            logger.debug("Failed to resolve directory objects via getByIds: %s", e)

    # Large per-ID fallback fans out aggressively and is what caused the 429 storm
    # during live operator testing. Keep the fallback budget tight.
    unresolved_ids = [x for x in valid_ids if x not in resolved]
    max_individual_fallback_ids = 8
    if unresolved_ids:
        if len(unresolved_ids) > max_individual_fallback_ids:
            logger.debug(
                "Skipping per-ID fallback for %d unresolved ID(s) to avoid Graph throttling",
                len(unresolved_ids),
            )
            return resolved, {
                "attempted": len(valid_ids),
                "resolved_count": len(resolved),
                "unresolved_count": len(unresolved_ids),
                "fallback_skipped_due_to_budget": True,
                "throttling_observed": throttling_observed,
                "sample_unresolved_ids": unresolved_ids[:5],
            }

        logger.debug(
            "Attempting individual fallback resolution for %d unresolved ID(s)", len(unresolved_ids)
        )
        for obj_id in unresolved_ids:
            # --------------------------------------------------------
            # 1. Try generic Directory Object first.
            # --------------------------------------------------------
            try:
                url_do = f"https://graph.microsoft.com/v1.0/directoryObjects/{obj_id}"
                resp_do = _graph_call(http, "GET", url_do, headers=headers)
                if resp_do.status_code == 200:
                    do_data = resp_do.json()
                    name = do_data.get("displayName") or do_data.get("userPrincipalName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_do.status_code == 429:
                    throttling_observed = True
            except Exception as ex_do:
                logger.debug("Failed to resolve directory object %s in fallback: %s", obj_id, ex_do)

            # --------------------------------------------------------
            # 2. Try Group
            # --------------------------------------------------------
            try:
                url_g = f"https://graph.microsoft.com/v1.0/groups/{obj_id}"
                resp_g = _graph_call(http, "GET", url_g, headers=headers)
                if resp_g.status_code == 200:
                    g_data = resp_g.json()
                    name = g_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_g.status_code == 429:
                    throttling_observed = True
            except Exception as ex_g:
                logger.debug("Failed to resolve group %s in fallback: %s", obj_id, ex_g)

            # --------------------------------------------------------
            # 3. Try User
            # --------------------------------------------------------
            try:
                url_u = f"https://graph.microsoft.com/v1.0/users/{obj_id}"
                resp_u = _graph_call(http, "GET", url_u, headers=headers)
                if resp_u.status_code == 200:
                    u_data = resp_u.json()
                    name = u_data.get("userPrincipalName") or u_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_u.status_code == 429:
                    throttling_observed = True
            except Exception as ex_u:
                logger.debug("Failed to resolve user %s in fallback: %s", obj_id, ex_u)

            # --------------------------------------------------------
            # 4. Try Service Principal
            # --------------------------------------------------------
            try:
                url_sp = f"https://graph.microsoft.com/v1.0/servicePrincipals/{obj_id}"
                resp_sp = _graph_call(http, "GET", url_sp, headers=headers)
                if resp_sp.status_code == 200:
                    sp_data = resp_sp.json()
                    name = sp_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_sp.status_code == 429:
                    throttling_observed = True
            except Exception as ex_sp:
                logger.debug(
                    "Failed to resolve service principal %s in fallback: %s", obj_id, ex_sp
                )

            # --------------------------------------------------------
            # 5. Try Directory Role
            # --------------------------------------------------------
            try:
                url_dr = f"https://graph.microsoft.com/v1.0/directoryRoles/{obj_id}"
                resp_dr = _graph_call(http, "GET", url_dr, headers=headers)
                if resp_dr.status_code == 200:
                    dr_data = resp_dr.json()
                    name = dr_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_dr.status_code == 429:
                    throttling_observed = True
            except Exception as ex_dr:
                logger.debug("Failed to resolve directory role %s in fallback: %s", obj_id, ex_dr)

            # --------------------------------------------------------
            # 6. Try Directory Role Definition
            # --------------------------------------------------------
            try:
                url_rd = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/{obj_id}"
                resp_rd = _graph_call(http, "GET", url_rd, headers=headers)
                if resp_rd.status_code == 200:
                    rd_data = resp_rd.json()
                    name = rd_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_rd.status_code == 429:
                    throttling_observed = True
            except Exception as ex_rd:
                logger.debug("Failed to resolve role definition %s in fallback: %s", obj_id, ex_rd)

            # --------------------------------------------------------
            # 7. Try Device
            # --------------------------------------------------------
            try:
                url_d = f"https://graph.microsoft.com/v1.0/devices/{obj_id}"
                resp_d = _graph_call(http, "GET", url_d, headers=headers)
                if resp_d.status_code == 200:
                    d_data = resp_d.json()
                    name = d_data.get("displayName")
                    if name:
                        resolved[obj_id] = name
                        continue
                if resp_d.status_code == 429:
                    throttling_observed = True
            except Exception as ex_d:
                logger.debug("Failed to resolve device %s in fallback: %s", obj_id, ex_d)

            # --------------------------------------------------------
            # 8. Try Directory Deleted Items (soft-deleted objects)
            # --------------------------------------------------------
            try:
                url_del = f"https://graph.microsoft.com/v1.0/directory/deletedItems/{obj_id}"
                resp_del = _graph_call(http, "GET", url_del, headers=headers)
                if resp_del.status_code == 200:
                    del_data = resp_del.json()
                    name = del_data.get("displayName") or del_data.get("userPrincipalName")
                    if name:
                        resolved[obj_id] = f"{name} (Deleted)"
                        continue
                if resp_del.status_code == 429:
                    throttling_observed = True
            except Exception as ex_del:
                logger.debug("Failed to resolve deleted item %s in fallback: %s", obj_id, ex_del)

    remaining = [x for x in valid_ids if x not in resolved]
    return resolved, {
        "attempted": len(valid_ids),
        "resolved_count": len(resolved),
        "unresolved_count": len(remaining),
        "fallback_skipped_due_to_budget": False,
        "throttling_observed": throttling_observed,
        "sample_unresolved_ids": remaining[:5],
    }


def resolve_directory_objects(
    http: httpx.Client, headers: dict[str, str], ids: list[str]
) -> dict[str, str]:
    """Backward-compatible wrapper returning only the resolved mapping."""
    resolved, _ = _resolve_directory_objects_with_diagnostics(http, headers, ids)
    return resolved


@technique(
    technique_id="discovery/entra_enum_conditional_access_policies",
    tactic="discovery",
    mitre_id="T1580",
    providers=["entra"],
    severity="info",
    safe=True,
    description="List all Conditional Access policies, including exclusions, to identify security bypass targets.",
    formatter=format_conditional_access_policies_result,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute CA Policy Enumeration."""
    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available."}

    if token.token_type == "refresh_token":
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed."}

    headers = {"Authorization": f"Bearer {token.value}"}
    parsed_policies = []
    partial_reasons: list[str] = []
    resolution = {
        "attempted": 0,
        "resolved_count": 0,
        "unresolved_count": 0,
        "fallback_skipped_due_to_budget": False,
        "throttling_observed": False,
        "sample_unresolved_ids": [],
    }

    with httpx.Client(timeout=30) as http:
        ctx.info("Enumerating Conditional Access policies...")
        try:
            policies = graph_list(
                http,
                "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                headers,
            )
        except GraphError as e:
            return graph_error_to_result(e, parsed_policies=[])

        # Collect all unique GUIDs referenced in policy targets
        guids = set()
        for p in policies:
            conditions = p.get("conditions") or {}
            users = conditions.get("users") or {}

            for item in users.get("includeUsers") or []:
                if item not in ["All", "None", "GuestsOrExternalUsers"]:
                    guids.add(item)
            for item in users.get("excludeUsers") or []:
                if item not in ["All", "None", "GuestsOrExternalUsers"]:
                    guids.add(item)
            for item in users.get("includeGroups") or []:
                if item not in ["All", "None"]:
                    guids.add(item)
            for item in users.get("excludeGroups") or []:
                if item not in ["All", "None"]:
                    guids.add(item)
            for item in users.get("includeRoles") or []:
                if item not in ["All", "None"]:
                    guids.add(item)
            for item in users.get("excludeRoles") or []:
                if item not in ["All", "None"]:
                    guids.add(item)

            apps_cond = conditions.get("applications") or {}
            for item in apps_cond.get("includeApplications") or []:
                if item not in ["All", "None", "Office365"]:
                    guids.add(item)
            for item in apps_cond.get("excludeApplications") or []:
                if item not in ["All", "None", "Office365"]:
                    guids.add(item)

            locs_cond = conditions.get("locations") or {}
            for item in locs_cond.get("includeLocations") or []:
                if item not in ["All", "AllTrusted", "None"]:
                    guids.add(item)
            for item in locs_cond.get("excludeLocations") or []:
                if item not in ["All", "AllTrusted", "None"]:
                    guids.add(item)

        # Build resolution map
        resolved = BUILTIN_ENTRA_ROLES.copy()
        resolved.update(WELL_KNOWN_APPS)

        # Resolve named locations first
        try:
            ctx.info("Fetching named locations from Graph...")
            locations = graph_list(
                http,
                "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations",
                headers,
            )
            for loc in locations:
                loc_id = loc.get("id")
                loc_name = loc.get("displayName")
                if loc_id and loc_name:
                    details = []
                    # Check for IP ranges
                    ip_ranges = loc.get("ipRanges") or []
                    for r in ip_ranges:
                        cidr = r.get("cidrAddress")
                        if cidr:
                            details.append(cidr)
                    # Check for countries/regions
                    countries = loc.get("countriesAndRegions") or []
                    for c in countries:
                        details.append(c)

                    if details:
                        if len(details) > 5:
                            display_str = (
                                ", ".join(details[:5]) + f", ... (+{len(details) - 5} more)"
                            )
                        else:
                            display_str = ", ".join(details)
                        resolved[loc_id] = f"{loc_name} ({display_str})"
                    else:
                        resolved[loc_id] = loc_name
        except Exception as ex:
            logger.debug("Failed to fetch named locations from Graph: %s", ex)

        # Resolve all directory role definitions dynamically
        try:
            ctx.info("Fetching directory role definitions from Graph...")
            role_defs = graph_list(
                http,
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions",
                headers,
            )
            for rd in role_defs:
                t_id = rd.get("templateId")
                r_id = rd.get("id")
                name = rd.get("displayName")
                if name:
                    if t_id:
                        resolved[t_id] = name
                    if r_id:
                        resolved[r_id] = name
        except Exception as ex:
            logger.debug("Failed to fetch role definitions from Graph: %s", ex)

        workspace = None
        if hasattr(ctx, "workspace"):
            workspace = ctx.workspace

        resolved.update(load_loot_mappings(workspace))

        unresolved = [g for g in guids if g not in resolved]
        if unresolved:
            ctx.info(f"Resolving {len(unresolved)} unique object ID(s) via Graph API...")
            api_resolved, resolution = _resolve_directory_objects_with_diagnostics(
                http, headers, unresolved
            )
            resolved.update(api_resolved)
            if resolution.get("unresolved_count", 0) > 0:
                partial_reasons.append("Directory object resolution incomplete")

        resolved_lower = {k.lower(): v for k, v in resolved.items() if k}

        def resolve_list(lst: list[str]) -> list[str]:
            res = []
            for item in lst:
                if not item:
                    res.append("")
                    continue
                item_str = str(item)
                res.append(resolved_lower.get(item_str.lower(), resolved.get(item_str, item_str)))
            return res

        for p in policies:
            # 1. Access Controls (Grant/Block)
            grant = p.get("grantControls") or {}
            grant_operator = grant.get("operator") or "OR"
            built_in = grant.get("builtInControls") or []

            controls_all = list(built_in)

            # 1.1 Authentication Strength
            auth_strength = grant.get("authenticationStrength") or {}
            auth_id = auth_strength.get("id")
            if auth_id:
                auth_name = resolved_lower.get(auth_id.lower(), resolved.get(auth_id))
                if not auth_name:
                    auth_name = auth_strength.get("displayName")
                if not auth_name:
                    well_known_strengths = {
                        "00000000-0000-0000-0000-000000000002": "MFA Strength",
                        "00000000-0000-0000-0000-000000000003": "Passwordless MFA Strength",
                        "00000000-0000-0000-0000-000000000004": "Phishing-Resistant MFA Strength",
                    }
                    auth_name = well_known_strengths.get(auth_id, f"authStrength({auth_id})")
                controls_all.append(f"authStrength({auth_name})")

            # 1.2 Terms of Use
            tou = grant.get("termsOfUse") or []
            for t_id in tou:
                t_name = resolved_lower.get(t_id.lower(), resolved.get(t_id, t_id))
                controls_all.append(f"termsOfUse({t_name})")

            # 1.3 Custom Authentication Factors
            caf = grant.get("customAuthenticationFactors") or []
            for c_id in caf:
                c_name = resolved_lower.get(c_id.lower(), resolved.get(c_id, c_id))
                controls_all.append(f"customAuth({c_name})")

            # 1.4 Session Controls
            session = p.get("sessionControls") or {}

            # Persistent Browser
            pb = session.get("persistentBrowser") or {}
            if pb.get("isEnabled"):
                pb_mode = pb.get("mode") or "unknown"
                controls_all.append(f"persistentBrowser({pb_mode})")

            # Sign-In Frequency
            sif = session.get("signInFrequency") or {}
            if sif.get("isEnabled"):
                sif_type = sif.get("type") or "unknown"
                sif_val = sif.get("value")
                if sif_val is not None:
                    controls_all.append(f"signInFrequency({sif_val} {sif_type})")
                else:
                    controls_all.append(f"signInFrequency({sif_type})")

            # Application Enforced Restrictions
            aer = session.get("applicationEnforcedRestrictions") or {}
            if aer.get("isEnabled"):
                controls_all.append("applicationEnforcedRestrictions")

            # Cloud App Security
            cas = session.get("cloudAppSecurity") or {}
            if cas.get("isEnabled"):
                cas_type = cas.get("cloudAppSecurityType") or "unknown"
                controls_all.append(f"cloudAppSecurity({cas_type})")

            # Continuous Access Evaluation
            cae = session.get("continuousAccessEvaluation") or {}
            cae_mode = cae.get("mode")
            if cae_mode:
                controls_all.append(f"continuousAccessEvaluation({cae_mode})")

            # Disable Resilience Defaults
            drd = session.get("disableResilienceDefaults")
            if drd is True:
                controls_all.append("disableResilienceDefaults(true)")

            # Secure Sign-In Session
            sss = session.get("secureSignInSession") or {}
            if sss.get("isEnabled"):
                controls_all.append("secureSignInSession")

            # Global Secure Access Filtering Profile
            gsaf = session.get("globalSecureAccessFilteringProfile") or {}
            if gsaf:
                profile_type = gsaf.get("profileType") or gsaf.get("profileId")
                if profile_type:
                    controls_all.append(f"globalSecureAccess({profile_type})")
                else:
                    # check if the dict is not completely empty
                    if any(gsaf.values()):
                        controls_all.append("globalSecureAccess")

            # 2. Scope - Users, Groups, Roles
            conditions = p.get("conditions") or {}
            users = conditions.get("users") or {}

            include_users = users.get("includeUsers") or []
            exclude_users = users.get("excludeUsers") or []

            include_groups = users.get("includeGroups") or []
            exclude_groups = users.get("excludeGroups") or []

            include_roles = users.get("includeRoles") or []
            exclude_roles = users.get("excludeRoles") or []

            # 3. Scope - Applications
            apps_cond = conditions.get("applications") or {}
            include_apps = apps_cond.get("includeApplications") or []
            exclude_apps = apps_cond.get("excludeApplications") or []

            # 4. Scope - Platforms
            platforms_cond = conditions.get("platforms") or {}
            include_platforms = platforms_cond.get("includePlatforms") or []
            exclude_platforms = platforms_cond.get("excludePlatforms") or []

            # 5. Scope - Locations
            locations_cond = conditions.get("locations") or {}
            include_locations = locations_cond.get("includeLocations") or []
            exclude_locations = locations_cond.get("excludeLocations") or []

            # 6. Scope - Client App Types
            client_apps = conditions.get("clientAppTypes") or []

            # 7. Missing fields
            sign_in_risk_levels = conditions.get("signInRiskLevels") or []
            user_risk_levels = conditions.get("userRiskLevels") or []
            sp_risk_levels = conditions.get("servicePrincipalRiskLevels") or []
            insider_risk_levels = conditions.get("insiderRiskLevels") or ""

            auth_flows = ""
            if conditions.get("authenticationFlows"):
                auth_flows = conditions["authenticationFlows"].get("transferMethods", "")

            devices_cond = conditions.get("devices") or {}
            device_filter = devices_cond.get("deviceFilter") or {}
            device_filter_mode = device_filter.get("mode") or ""
            device_filter_rule = device_filter.get("rule") or ""

            include_guest_types = ""
            exclude_guest_types = ""
            if users.get("includeGuestsOrExternalUsers"):
                ig = users["includeGuestsOrExternalUsers"]
                include_guest_types = ig.get("guestOrExternalUserTypes", "")
            if users.get("excludeGuestsOrExternalUsers"):
                eg = users["excludeGuestsOrExternalUsers"]
                exclude_guest_types = eg.get("guestOrExternalUserTypes", "")

            include_user_actions = apps_cond.get("includeUserActions") or []
            include_auth_context = (
                apps_cond.get("includeAuthenticationContextClassReferences") or []
            )

            # Serialize session controls
            sif = session.get("signInFrequency") or {}
            sif_val = sif.get("value", "")
            sif_type = sif.get("type", "")
            session_sign_in_freq = f"{sif_val} {sif_type}".strip() if sif.get("isEnabled") else ""

            pb = session.get("persistentBrowser") or {}
            session_persistent_browser = pb.get("mode", "") if pb.get("isEnabled") else ""

            sss = session.get("secureSignInSession") or {}
            session_token_protection = "true" if sss.get("isEnabled") else "false"

            cas = session.get("cloudAppSecurity") or {}
            session_casb = cas.get("cloudAppSecurityType", "") if cas.get("isEnabled") else ""

            resolved_inc_u = resolve_list(include_users)
            resolved_exc_u = resolve_list(exclude_users)
            resolved_inc_g = resolve_list(include_groups)
            resolved_exc_g = resolve_list(exclude_groups)
            resolved_inc_r = resolve_list(include_roles)
            resolved_exc_r = resolve_list(exclude_roles)
            resolved_inc_a = resolve_list(include_apps)
            resolved_exc_a = resolve_list(exclude_apps)
            resolved_inc_loc = resolve_list(include_locations)
            resolved_exc_loc = resolve_list(exclude_locations)

            parsed_policies.append(
                {
                    "display_name": p.get("displayName"),
                    "state": p.get("state"),
                    "grant_operator": grant_operator,
                    "grant_controls": ", ".join(controls_all) if controls_all else "None",
                    "included_users": ", ".join(resolved_inc_u) if resolved_inc_u else "None",
                    "excluded_users": ", ".join(resolved_exc_u) if resolved_exc_u else "None",
                    "include_guest_types": include_guest_types,
                    "exclude_guest_types": exclude_guest_types,
                    "included_groups": ", ".join(resolved_inc_g) if resolved_inc_g else "None",
                    "excluded_groups": ", ".join(resolved_exc_g) if resolved_exc_g else "None",
                    "included_roles": ", ".join(resolved_inc_r) if resolved_inc_r else "None",
                    "excluded_roles": ", ".join(resolved_exc_r) if resolved_exc_r else "None",
                    "included_apps": ", ".join(resolved_inc_a) if resolved_inc_a else "None",
                    "excluded_apps": ", ".join(resolved_exc_a) if resolved_exc_a else "None",
                    "include_user_actions": ", ".join(include_user_actions)
                    if include_user_actions
                    else "None",
                    "include_auth_context": ", ".join(include_auth_context)
                    if include_auth_context
                    else "None",
                    "included_platforms": ", ".join(include_platforms)
                    if include_platforms
                    else "All",
                    "exclude_platforms": ", ".join(exclude_platforms)
                    if exclude_platforms
                    else "None",
                    "included_locations": ", ".join(resolved_inc_loc)
                    if resolved_inc_loc
                    else "All",
                    "excluded_locations": ", ".join(resolved_exc_loc)
                    if resolved_exc_loc
                    else "None",
                    # Structured lists preserve entries containing CIDR commas — see B3.
                    # `get_list()` prefers these fields when present so callers no
                    # longer split a single "IPs (a, b)" string into three entries.
                    "included_locations_list": list(resolved_inc_loc) if resolved_inc_loc else [],
                    "excluded_locations_list": list(resolved_exc_loc) if resolved_exc_loc else [],
                    "client_app_types": ", ".join(client_apps) if client_apps else "All",
                    "sign_in_risk_levels": ", ".join(sign_in_risk_levels)
                    if sign_in_risk_levels
                    else "None",
                    "user_risk_levels": ", ".join(user_risk_levels) if user_risk_levels else "None",
                    "sp_risk_levels": ", ".join(sp_risk_levels) if sp_risk_levels else "None",
                    "insider_risk_levels": insider_risk_levels,
                    "auth_flows": auth_flows,
                    "device_filter_mode": device_filter_mode,
                    "device_filter_rule": device_filter_rule,
                    "session_sign_in_freq": session_sign_in_freq,
                    "session_persistent_browser": session_persistent_browser,
                    "session_token_protection": session_token_protection,
                    "session_casb": session_casb,
                    "id": p.get("id"),
                }
            )

        # Generate findings for active bypass opportunities
        if getattr(ctx, "workspace", None):
            for p in parsed_policies:
                name = p.get("display_name")
                state = p.get("state")
                controls = p.get("grant_controls")

                # Active bypass findings
                if state == "enabled":
                    # Explain controls to append to description
                    exps = explain_controls(controls)
                    exp_suffix = ""
                    if exps:
                        exp_suffix = "\n\nControl Explanations:\n" + "\n".join(
                            f"- {e}" for e in exps
                        )

                    # Excluded users
                    ex_u = get_list(p.get("excluded_users"))
                    if ex_u:
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Exclusion: Users Excluded from '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"User(s) {', '.join(ex_u)} are excluded from policy '{name}' and can bypass controls ({controls}).{exp_suffix}",
                            evidence=json.dumps(
                                {"policy_name": name, "excluded_users": ex_u, "controls": controls}
                            ),
                            mitre_id="T1580",
                        )
                    # Excluded groups
                    ex_g = get_list(p.get("excluded_groups"))
                    if ex_g:
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Exclusion: Groups Excluded from '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"Group(s) {', '.join(ex_g)} are excluded from policy '{name}'. Members bypass controls ({controls}).{exp_suffix}",
                            evidence=json.dumps(
                                {"policy_name": name, "excluded_groups": ex_g, "controls": controls}
                            ),
                            mitre_id="T1580",
                        )
                    # Excluded roles
                    ex_r = get_list(p.get("excluded_roles"))
                    if ex_r:
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Exclusion: Roles Excluded from '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"Role(s) {', '.join(ex_r)} are excluded from policy '{name}'. Role members bypass controls ({controls}).{exp_suffix}",
                            evidence=json.dumps(
                                {"policy_name": name, "excluded_roles": ex_r, "controls": controls}
                            ),
                            mitre_id="T1580",
                        )
                    # Excluded platforms
                    ex_p = get_list(p.get("exclude_platforms"))
                    if ex_p:
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Bypass: Platforms Excluded from '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"Platform(s) {', '.join(ex_p)} are excluded from policy '{name}'. Spoofing User-Agent to these platforms bypasses controls ({controls}).{exp_suffix}",
                            evidence=json.dumps(
                                {
                                    "policy_name": name,
                                    "excluded_platforms": ex_p,
                                    "controls": controls,
                                }
                            ),
                            mitre_id="T1580",
                        )
                    # Excluded locations
                    ex_loc = get_list_from_policy(p, "excluded_locations")
                    if ex_loc:
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Bypass: Locations Excluded from '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"Location(s) {', '.join(ex_loc)} are excluded from policy '{name}'. Accessing from these networks/locations bypasses controls ({controls}).{exp_suffix}",
                            evidence=json.dumps(
                                {
                                    "policy_name": name,
                                    "excluded_locations": ex_loc,
                                    "controls": controls,
                                }
                            ),
                            mitre_id="T1580",
                        )
                    # Legacy auth allowed
                    client_apps = [x.lower() for x in get_list(p.get("client_app_types"))]
                    if "exchangeactivesync" in client_apps or "other" in client_apps:
                        legacy_clients = [
                            c for c in client_apps if c in ["exchangeactivesync", "other"]
                        ]
                        ctx.workspace.add_finding(
                            technique_id="discovery/entra_enum_conditional_access_policies",
                            tactic="discovery",
                            title=f"Conditional Access Bypass: Legacy Authentication Allowed in '{name}'",
                            severity="medium",
                            provider="entra",
                            description=f"Legacy authentication protocols ({', '.join(legacy_clients)}) are allowed in policy '{name}'. Attackers can bypass modern MFA controls using legacy authentication.{exp_suffix}",
                            evidence=json.dumps(
                                {"policy_name": name, "client_app_types": client_apps}
                            ),
                            mitre_id="T1580",
                        )

    status = "partial" if partial_reasons else "success"

    return {
        "provider": "entra",
        "status": status,
        "policies": parsed_policies,
        "tenant_id": store.tenant_id,
        "partial_reasons": partial_reasons,
        "resolution": resolution,
    }


def explain_controls(controls_str: str) -> list[str]:
    """
    Translates raw Conditional Access policy control terms into plain English
    and provides clear explanations of what they mean under Bypass / Pentesting context.
    """
    if not controls_str or controls_str == "None":
        return []

    import re

    parts = []
    current = []
    depth = 0
    for char in controls_str:
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            current.append(char)
    if current:
        parts.append("".join(current).strip())

    explanations = []
    for part in parts:
        if not part:
            continue

        # 1. persistentBrowser
        pb_match = re.match(r"persistentBrowser\((.+?)\)", part, re.IGNORECASE)
        if pb_match:
            mode = pb_match.group(1).strip()
            if mode.lower() == "never":
                explanations.append(
                    "persistentBrowser(never): Persistent browser sessions are disabled. Users are forced to re-authenticate when they close and reopen their browser (session cookies do not persist). This mitigates the risk of stolen session hijacking via local cookie extraction."
                )
            elif mode.lower() == "always":
                explanations.append(
                    "persistentBrowser(always): Persistent browser sessions are enabled/enforced. Stolen/hijacked session cookies remain valid across browser restarts, representing a persistent access risk. Attackers can hijack these sessions to maintain long-term access without re-triggering MFA."
                )
            else:
                explanations.append(
                    f"persistentBrowser({mode}): Persistent browser session control is set to '{mode}'."
                )
            continue

        # 2. signInFrequency
        sif_match = re.match(r"signInFrequency\((.+?)\)", part, re.IGNORECASE)
        if sif_match:
            val = sif_match.group(1).strip()
            explanations.append(
                f"signInFrequency({val}): Limits the lifetime of the authentication session. The user must re-authenticate every {val}. From a pentester's perspective, this limits the lifespan/window of opportunity for any stolen or hijacked session token/cookie."
            )
            continue

        # 3. authStrength
        as_match = re.match(r"authStrength\((.+?)\)", part, re.IGNORECASE)
        if as_match:
            strength = as_match.group(1).strip()
            explanations.append(
                f"authStrength({strength}): Enforces a specific set of authentication methods (e.g., {strength}). Bypassing this requires enrolling/accessing a compliant factor, or finding exclusions/fallback authentication methods."
            )
            continue

        # 4. termsOfUse
        tou_match = re.match(r"termsOfUse\((.+?)\)", part, re.IGNORECASE)
        if tou_match:
            tou = tou_match.group(1).strip()
            explanations.append(
                f"termsOfUse({tou}): User must accept the '{tou}' Terms of Use agreement. Pentesters must accept these terms during login to proceed."
            )
            continue

        # 5. customAuth
        ca_match = re.match(r"customAuth\((.+?)\)", part, re.IGNORECASE)
        if ca_match:
            ca = ca_match.group(1).strip()
            explanations.append(
                f"customAuth({ca}): Requires a custom authentication provider/factor '{ca}'."
            )
            continue

        # 6. cloudAppSecurity
        cas_match = re.match(r"cloudAppSecurity\((.+?)\)", part, re.IGNORECASE)
        if cas_match:
            cas_type = cas_match.group(1).strip()
            explanations.append(
                f"cloudAppSecurity({cas_type}): Redirects session traffic through Microsoft Defender for Cloud Apps for real-time monitoring and control."
            )
            continue

        # 7. continuousAccessEvaluation
        cae_match = re.match(r"continuousAccessEvaluation\((.+?)\)", part, re.IGNORECASE)
        if cae_match:
            cae_mode = cae_match.group(1).strip()
            explanations.append(
                f"continuousAccessEvaluation({cae_mode}): Enforces near real-time revocation of active sessions on critical events (e.g. password change, IP address change, account disablement)."
            )
            continue

        # 8. globalSecureAccess
        gsa_match = re.match(r"globalSecureAccess\((.+?)\)", part, re.IGNORECASE)
        if gsa_match:
            gsa_profile = gsa_match.group(1).strip()
            explanations.append(
                f"globalSecureAccess({gsa_profile}): Routes traffic through Global Secure Access (SSE) edge, enforcing network-level policies."
            )
            continue
        elif part.lower() == "globalsecureaccess":
            explanations.append(
                "globalSecureAccess: Routes traffic through Global Secure Access (SSE) edge, enforcing network-level policies."
            )
            continue

        # 9. disableResilienceDefaults
        drd_match = re.match(r"disableResilienceDefaults\((.+?)\)", part, re.IGNORECASE)
        if drd_match:
            drd_val = drd_match.group(1).strip()
            explanations.append(
                f"disableResilienceDefaults({drd_val}): Disables Entra ID's resilience backup during outages, meaning authentication attempts won't fallback to cached states if a service outage occurs."
            )
            continue

        # 10. Built-in / Static Controls
        if part.lower() == "mfa":
            explanations.append(
                "mfa: Requires standard Multifactor Authentication (e.g., Microsoft Authenticator, SMS, or Voice). Can be targeted via MFA fatigue (push bombing), AiTM (Adversary-in-the-Middle) phishing, or legacy protocol bypass if allowed."
            )
        elif part.lower() == "block":
            explanations.append(
                "block: Explicitly blocks access. If you are hitting this policy, search for exclusions, try spoofing your location/IP if location-based, or access via a non-targeted user/group/platform."
            )
        elif part.lower() == "passwordchange":
            explanations.append(
                "passwordChange: User must change their password. Typically triggered by high user risk. Pentesters must complete the password reset flow to gain normal access."
            )
        elif part.lower() == "applicationenforcedrestrictions":
            explanations.append(
                "applicationEnforcedRestrictions: Enforces app-specific restrictions (e.g. limiting access/downloads in SharePoint/Exchange Web Access based on device state)."
            )
        elif part.lower() == "securesigninsession":
            explanations.append(
                "secureSignInSession: Enforces additional session protection during sign-in."
            )
        else:
            explanations.append(f"{part}: Active access control/restriction policy.")

    return explanations
