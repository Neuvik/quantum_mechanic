# ================================================================
# TECHNIQUE: discovery/unified_enum_users
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Accounts
#
# PURPOSE:   Enumerate user accounts across any cloud provider.
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
LOOT_ITEMS_KEY = 'users'
LOOT_SCHEMA = [
    ('username', 'Username/UPN', 'bold cyan'),
    ('type',     'Type',         'white'),
    ('id',       'ID',           'dim'),
    ('info',     'Info',         'dim'),
]

def format_unified_users(result: Any) -> None:
    """Formatter for Unified User discovery results."""
    from rich.table import Table
    from quantum_mechanic.shell.formatters import console

    data = result.data
    users = data.get("users", [])
    provider = result.provider.upper()

    if not users:
        console.print(f"  [dim]No users discovered for {provider} (or access denied).[/dim]")
        return

    console.print(f"  [bold green]✓[/bold green] Discovered [bold cyan]{len(users)}[/bold cyan] {provider} User(s)")
    
    tbl = Table(box=None, padding=(0, 2), show_header=True)
    tbl.add_column("Username/UPN", style="bold cyan")
    tbl.add_column("Type", style="white")
    tbl.add_column("ID", style="dim")
    tbl.add_column("Info", style="dim")

    # Limit display to first 100 for brevity in the shell
    for u in users[:100]:
        tbl.add_row(
            u.get("username", "—"),
            u.get("type", "—"),
            u.get("id", "—"),
            u.get("info", "—")
        )
            
    console.print(tbl)
    if len(users) > 100:
        console.print(f"  [dim]... and {len(users) - 100} more users in result data[/dim]")

@technique(
    technique_id="discovery/unified_enum_users",
    tactic='discovery',
    mitre_id="T1087.004",
    providers=["aws", "azure", "gcp", "oci", "entra"],
    severity="info",
    safe=True,
    description="Enumerate all users across any cloud provider (IAM, Graph, Project members).",
    formatter=format_unified_users,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Unified User discovery."""
    dispatch = {
        "aws": _enum_aws,
        "azure": _enum_azure,
        "gcp": _enum_gcp,
        "oci": _enum_oci,
        "entra": _enum_entra,
    }
    
    handler = dispatch.get(ctx.provider_name)
    if handler is None:
        return {"error": f"Provider {ctx.provider_name} not implemented.", "users": []}
        
    return handler(ctx)

# ================================================================
# AWS — IAM User Discovery
# ================================================================

def _enum_aws(ctx: ExecutionContext) -> dict[str, Any]:
    iam = ctx.session.client("iam")
    users = []

    try:
        paginator = iam.get_paginator('list_users')
        ctx.info("Enumerating AWS IAM users...")
        for page in paginator.paginate():
            for u in page.get("Users", []):
                users.append({
                    "username": u["UserName"],
                    "type": "IAM User",
                    "id": u["UserId"],
                    "info": f"Created: {u['CreateDate'].strftime('%Y-%m-%d')}"
                })
        ctx.success(f"Discovered {len(users)} AWS users.")
    except Exception as e:
        ctx.debug(f"AWS IAM user enumeration failed: {e}")
        return {"error": str(e), "users": []}

    return {"status": "success", "users": users}

# ================================================================
# Azure / Entra — delegate to entra_enum_users (authoritative)
# ================================================================

from quantum_mechanic.techniques.discovery import entra_enum_users

def _enum_azure(ctx: ExecutionContext) -> dict[str, Any]:
    return _enum_entra(ctx)

def _enum_entra(ctx: ExecutionContext) -> dict[str, Any]:
    return entra_enum_users.execute(ctx)

# ================================================================
# GCP — Project Member Discovery
# ================================================================

def _enum_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return {"error": "GCP SDK not installed.", "users": []}

    users = []
    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    
    whoami = ctx.whoami()
    project_id = whoami.account_id
    
    if not project_id or project_id == "unknown":
        return {"error": "No GCP project identified.", "users": []}

    try:
        ctx.info(f"Enumerating GCP project members for {project_id}...")
        req = {"resource": f"projects/{project_id}"}
        policy = client.get_iam_policy(request=req)

        # Map members to roles and unique users
        seen_members = {}
        for binding in policy.bindings:
            for member in binding.members:
                if member not in seen_members:
                    mtype = member.split(":", 1)[0].title() if ":" in member else "Unknown"
                    name = member.split(":", 1)[-1] if ":" in member else member
                    seen_members[member] = {
                        "username": name,
                        "type": mtype,
                        "id": member,
                        "info": f"Role: {binding.role.split('/')[-1]}"
                    }
                else:
                    # Append additional roles if member seen before
                    role_short = binding.role.split('/')[-1]
                    if role_short not in seen_members[member]["info"]:
                        seen_members[member]["info"] += f", {role_short}"

        users = list(seen_members.values())
        ctx.success(f"Discovered {len(users)} GCP project members.")
    except Exception as e:
        ctx.debug(f"GCP IAM scan failed for {project_id}: {e}")
        return {"error": str(e), "users": []}

    return {"status": "success", "users": users}

# ================================================================
# OCI — Identity User Discovery
# ================================================================

def _enum_oci(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        import oci
    except ImportError:
        return {"error": "OCI SDK not installed.", "users": []}

    users = []
    config = ctx.session["config"]
    signer = ctx.session.get("signer")
    
    identity = oci.identity.IdentityClient(config, signer=signer) if signer else oci.identity.IdentityClient(config)
    tenancy_id = config.get("tenancy")

    try:
        ctx.info("Enumerating OCI Identity users...")
        # Use oci.pagination to handle large result sets automatically
        all_users = oci.pagination.list_call_get_all_results(identity.list_users, tenancy_id).data
        for u in all_users:
            users.append({
                "username": u.name,
                "type": "OCI User",
                "id": u.id,
                "info": f"State: {u.lifecycle_state}"
            })
        ctx.success(f"Discovered {len(users)} OCI users.")
    except Exception as e:
        ctx.debug(f"OCI user enumeration failed: {e}")
        return {"error": str(e), "users": []}

    return {"status": "success", "users": users}
