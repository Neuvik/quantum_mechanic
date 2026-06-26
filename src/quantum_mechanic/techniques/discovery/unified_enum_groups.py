# ================================================================
# TECHNIQUE: discovery/unified_enum_groups
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1069.003 — Permission Groups: Cloud Groups
#
# PURPOSE:   Identify groups and their members across any cloud
#            provider.
#
# PROVIDERS: AWS, Azure, GCP, OCI, Entra
#
# SAFE:      Yes — completely read-only.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'groups'
LOOT_SCHEMA = [
    ('name',        'Group Name',  'bold cyan'),
    ('id',          'Group ID',    'white'),
    ('members',     'Members',     'bold yellow'),
    ('description', 'Description', 'dim'),
]

def format_unified_groups(result: Any) -> None:
    """Formatter for Unified Group discovery results."""
    from rich.table import Table
    from rich import box
    from quantum_mechanic.shell.formatters import console

    data = result.data
    groups = data.get("groups", [])
    provider = result.provider.upper()

    if not groups:
        console.print(f"  [dim]No groups discovered for {provider} (or access denied).[/dim]")
        return

    console.print(f"  [bold green]✓[/bold green] Discovered [bold cyan]{len(groups)}[/bold cyan] {provider} Group(s)")
    
    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Group Name", style="bold cyan")
    tbl.add_column("Group ID", style="white")
    tbl.add_column("Members", style="bold yellow")
    tbl.add_column("Description", style="dim")

    for g in groups:
        tbl.add_row(
            g.get("name", "—"),
            g.get("id", "—"),
            str(g.get("members", 0)),
            g.get("description", "—")
        )
            
    console.print(tbl)

@technique(
    technique_id="discovery/unified_enum_groups",
    tactic='discovery',
    mitre_id="T1069.003",
    providers=["aws", "azure", "gcp", "oci", "entra"],
    severity="info",
    safe=True,
    description="Enumerate cloud identity groups and their memberships.",
    formatter=format_unified_groups,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Unified Group discovery."""
    dispatch = {
        "aws": _enum_aws,
        "azure": _enum_azure,
        "gcp": _enum_gcp,
        "oci": _enum_oci,
        "entra": _enum_entra,
    }
    
    handler = dispatch.get(ctx.provider_name)
    if handler is None:
        return {"error": f"Provider {ctx.provider_name} not implemented.", "groups": []}
        
    return handler(ctx)

# ================================================================
# AWS — IAM Group Discovery
# ================================================================

def _enum_aws(ctx: ExecutionContext) -> dict[str, Any]:
    iam = ctx.session.client("iam")
    groups_out = []

    try:
        ctx.info("Listing AWS IAM groups...")
        paginator = iam.get_paginator('list_groups')
        
        for page in paginator.paginate():
            for g in page.get('Groups', []):
                gname = g['GroupName']
                gid = g['GroupId']
                
                # Resolve members
                member_count = 0
                try:
                    # get_group returns the group and its users
                    group_resp = iam.get_group(GroupName=gname)
                    member_count = len(group_resp.get('Users', []))
                except Exception as e:
                    ctx.debug(f"Failed to get members for group {gname}: {e}")

                groups_out.append({
                    "name": gname,
                    "id": gid,
                    "members": member_count,
                    "description": f"Path: {g['Path']}"
                })
        
        ctx.success(f"Discovered {len(groups_out)} IAM groups.")
    except Exception as e:
        ctx.error(f"AWS IAM group scan failed: {e}")
        return {"status": "error", "error": str(e), "groups": []}

    return {"status": "success", "groups": groups_out}

# ================================================================
# Azure / Entra — Graph Group Discovery
# ================================================================

def _enum_entra(ctx: ExecutionContext) -> dict[str, Any]:
    return _enum_graph(ctx, provider_label="Entra")

def _enum_azure(ctx: ExecutionContext) -> dict[str, Any]:
    # Azure AD groups are accessed via Graph. 
    # We attempt to use the same logic, but the session might be different.
    return _enum_graph(ctx, provider_label="Azure")

def _enum_graph(ctx: ExecutionContext, provider_label: str) -> dict[str, Any]:
    from quantum_mechanic.providers.entra.token_store import GRAPH
    from quantum_mechanic.providers.entra.graph import graph_list

    groups_out = []
    
    # In Entra provider, ctx.session is EntraTokenStore
    # In Azure provider, it might be different, but we check if we can get a Graph token
    store = ctx.session
    token = None
    
    if hasattr(store, "best_token"):
        token = store.best_token(GRAPH)
    
    if not token:
        # Try to fall back to environment or interactive if possible? 
        # For now, if no token, we can't do much.
        ctx.debug(f"No Graph token available for {provider_label} group discovery.")
        return {"status": "error", "error": "No Graph token available.", "groups": []}
        
    headers = {"Authorization": f"Bearer {token.value}"}

    try:
        ctx.info(f"Listing {provider_label} groups via Microsoft Graph...")
        with httpx.Client(timeout=30) as http:
            # List groups
            groups = graph_list(http, "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description", headers)
            
            for g in groups:
                gid = g.get("id")
                name = g.get("displayName")
                desc = g.get("description", "")
                
                # Resolve member count
                # We use /$count which requires ConsistencyLevel: eventual but that's for advanced filtering.
                # A simpler way is to just list members, but that can be slow.
                # Graph also supports /members/$count if we use the right headers.
                # But to keep it simple and compatible, we'll try to get the members.
                member_count = 0
                try:
                    # We only need the count, so $top=1 might be enough if we just want to see if it's empty,
                    # but we want the actual count.
                    # Unfortunately, Graph doesn't always return @odata.count unless requested with $count=true
                    # and ConsistencyLevel: eventual header.
                    
                    # For a "heuristic" scan, let's just fetch members with a small top and see.
                    # Or better, use the $count feature if possible.
                    count_headers = headers.copy()
                    count_headers["ConsistencyLevel"] = "eventual"
                    count_url = f"https://graph.microsoft.com/v1.0/groups/{gid}/members/$count"
                    resp = http.get(count_url, headers=count_headers)
                    if resp.status_code == 200:
                        member_count = int(resp.text)
                    else:
                        # Fallback: list members (might be capped by graph_list default)
                        m_list = graph_list(http, f"https://graph.microsoft.com/v1.0/groups/{gid}/members?$select=id", headers, max_pages=1)
                        member_count = len(m_list)
                except Exception:
                    pass

                groups_out.append({
                    "name": name,
                    "id": gid,
                    "members": member_count,
                    "description": desc
                })
        
        ctx.success(f"Discovered {len(groups_out)} {provider_label} groups.")
    except Exception as e:
        ctx.debug(f"{provider_label} Graph scan failed: {e}")
        return {"status": "error", "error": str(e), "groups": []}

    return {"status": "success", "groups": groups_out}

# ================================================================
# GCP — Project IAM Policy Group Extraction
# ================================================================

def _enum_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return {"error": "GCP SDK not installed.", "groups": []}

    groups_out = []
    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    
    whoami = ctx.whoami()
    project_id = whoami.account_id
    
    if not project_id or project_id == "unknown":
        return {"error": "No GCP project identified.", "groups": []}

    try:
        ctx.info(f"Analyzing IAM policy for project {project_id} to extract groups...")
        req = {"resource": f"projects/{project_id}"}
        policy = client.get_iam_policy(request=req)

        # Map group email -> list of roles
        group_map = {}

        for binding in policy.bindings:
            for member in binding.members:
                if member.startswith("group:"):
                    email = member.replace("group:", "")
                    if email not in group_map:
                        group_map[email] = []
                    group_map[email].append(binding.role)

        for email, roles in group_map.items():
            groups_out.append({
                "name": email,
                "id": email,
                "members": "Unknown", # Cannot resolve members via project IAM policy alone
                "description": f"Roles: {', '.join(roles)}"
            })
            
        ctx.success(f"Identified {len(groups_out)} groups from project IAM policy.")
    except Exception as e:
        ctx.debug(f"GCP IAM group extraction failed: {e}")
        return {"status": "error", "error": str(e), "groups": []}

    return {"status": "success", "groups": groups_out}

# ================================================================
# OCI — Identity Group Discovery
# ================================================================

def _enum_oci(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        import oci
        from oci.pagination import list_call_get_all_results
    except ImportError:
        return {"error": "OCI SDK not installed.", "groups": []}

    groups_out = []
    config = ctx.session["config"]
    signer = ctx.session.get("signer")
    
    identity = oci.identity.IdentityClient(config, signer=signer) if signer else oci.identity.IdentityClient(config)
    tenancy_id = config.get("tenancy")

    try:
        ctx.info("Listing OCI groups...")
        groups = list_call_get_all_results(identity.list_groups, tenancy_id).data
        
        for g in groups:
            # Resolve members
            member_count = 0
            try:
                memberships = list_call_get_all_results(
                    identity.list_user_group_memberships, 
                    tenancy_id, 
                    group_id=g.id
                ).data
                member_count = len(memberships)
            except Exception as e:
                ctx.debug(f"Failed to list members for OCI group {g.name}: {e}")

            groups_out.append({
                "name": g.name,
                "id": g.id,
                "members": member_count,
                "description": g.description or ""
            })
            
        ctx.success(f"Discovered {len(groups_out)} OCI groups.")
    except Exception as e:
        ctx.debug(f"OCI group scan failed: {e}")
        return {"status": "error", "error": str(e), "groups": []}

    return {"status": "success", "groups": groups_out}
