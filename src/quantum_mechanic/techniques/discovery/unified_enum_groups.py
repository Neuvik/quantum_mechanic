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
# Azure / Entra — delegate to entra_enum_groups (authoritative)
# ================================================================

from quantum_mechanic.techniques.discovery import entra_enum_groups

def _enum_azure(ctx: ExecutionContext) -> dict[str, Any]:
    return _enum_entra(ctx)

def _enum_entra(ctx: ExecutionContext) -> dict[str, Any]:
    result = entra_enum_groups.execute(ctx)
    for g in result.get("groups", []):
        g.setdefault("name", g.get("displayName", "—"))
        g.setdefault("members", 0)
    return result

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
