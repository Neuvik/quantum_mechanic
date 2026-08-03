# ================================================================
# TECHNIQUE: discovery/unified_enum_admins
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1078.004 — Cloud Accounts
#
# PURPOSE:   Identify the "obvious" high-privilege principals in
#            the current account/subscription/project.
#
# PROVIDERS: AWS, Azure, GCP, OCI, Entra
#
# CAUTION:   This is a HEURISTIC scan for "low-hanging fruit" admin
#            assignments. It is NOT an exhaustive policy evaluation.
#            Shadow admins, complex IAM conditions, or nested group
#            memberships may not be visible.
#
# DEEPER ANALYSIS TOOLS:
#   AWS:   CloudFox (https://github.com/redpointlabs/cloudfox)
#   Azure: AzureHound / BloodHound (https://github.com/BloodHoundAD)
#   GCP:   GCP-Scanner (https://github.com/google/gcp-scanner)
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
LOOT_ITEMS_KEY = 'admins'
LOOT_SCHEMA = [
    ('principal', 'Principal', 'bold cyan'),
    ('type',      'Type',      'white'),
    ('role',      'Role/Policy', 'bold yellow'),
    ('reason',    'Reason',    'dim'),
]

def format_unified_admins(result: Any) -> None:
    """Formatter for Unified Admin discovery results."""
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from quantum_mechanic.shell.formatters import console

    data = result.data
    admins = data.get("admins", [])
    provider = result.provider.upper()

    # --- THE CAUTION / DISCLAIMER ---
    console.print(Panel(
        "[bold red]⚠ HEURISTIC SCAN DISCLAIMER[/bold red]\n"
        "This module identifies [bold]obvious[/bold] administrator assignments only.\n"
        "It does [bold]NOT[/bold] perform exhaustive policy evaluation or graph-based analysis.\n\n"
        "[dim]For deep visibility, we recommend:[/dim]\n"
        "• [cyan]AWS:[/cyan]   CloudFox\n"
        "• [cyan]Azure:[/cyan] AzureHound / BloodHound\n"
        "• [cyan]GCP:[/cyan]   GCP-Scanner",
        border_style="yellow",
        expand=False
    ))

    if not admins:
        console.print(f"  [dim]No obvious {provider} admins discovered (or access denied).[/dim]")
        return

    console.print(f"  [bold green]✓[/bold green] Discovered [bold cyan]{len(admins)}[/bold cyan] obvious {provider} Admin(s)")
    
    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Principal", style="bold cyan")
    tbl.add_column("Type", style="white")
    tbl.add_column("Role / Policy", style="bold yellow")
    tbl.add_column("Reason", style="dim")

    for a in admins:
        tbl.add_row(
            a.get("principal", "—"),
            a.get("type", "—"),
            a.get("role", "—"),
            a.get("reason", "—")
        )
            
    console.print(tbl)

@technique(
    technique_id="discovery/unified_enum_admins",
    tactic='discovery',
    mitre_id="T1078.004",
    providers=["aws", "azure", "gcp", "oci", "entra"],
    severity="info",
    safe=True,
    description="Identify obvious high-privilege principals (Owners, Administrators) across any cloud provider.",
    formatter=format_unified_admins,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute Unified Admin discovery."""
    dispatch = {
        "aws": _enum_aws,
        "azure": _enum_azure,
        "gcp": _enum_gcp,
        "oci": _enum_oci,
        "entra": _enum_entra,
    }
    
    handler = dispatch.get(ctx.provider_name)
    if handler is None:
        return {"error": f"Provider {ctx.provider_name} not implemented.", "admins": []}
        
    return handler(ctx)

# ================================================================
# AWS — IAM Admin Discovery
# ================================================================

def _enum_aws(ctx: ExecutionContext) -> dict[str, Any]:
    iam = ctx.session.client("iam")
    admins = []

    # 1. Check for the canonical AdministratorAccess policy
    try:
        arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        ctx.debug(f"Checking for entities with {arn}")
        resp = iam.list_entities_for_policy(PolicyArn=arn)
        
        for u in resp.get("PolicyUsers", []):
            admins.append({
                "principal": u["UserName"],
                "type": "User",
                "role": "AdministratorAccess",
                "reason": "Full Administrative Rights (AWS Managed)"
            })
        for r in resp.get("PolicyRoles", []):
            admins.append({
                "principal": r["RoleName"],
                "type": "Role",
                "role": "AdministratorAccess",
                "reason": "Full Administrative Rights (AWS Managed)"
            })
    except Exception as e:
        ctx.debug(f"Failed to list entities for AdministratorAccess: {e}")

    # 2. Check for the local 'Admins' group (common pattern)
    try:
        ctx.debug("Checking for local 'Admins' or 'Administrators' groups")
        for gname in ["Admins", "Administrators", "Admin"]:
            try:
                resp = iam.get_group(GroupName=gname)
                for u in resp.get("Users", []):
                    admins.append({
                        "principal": u["UserName"],
                        "type": "User",
                        "role": f"Group: {gname}",
                        "reason": "Member of suspected admin group"
                    })
            except Exception:
                continue
    except Exception:
        pass

    return {"status": "success", "admins": admins}

# ================================================================
# Azure — RBAC Owner/Contributor Discovery
# ================================================================

def _enum_azure(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "Azure SDKs not installed."}

    admins = []
    sub_client = SubscriptionClient(ctx.session)
    
    # Track which IDs we've seen to avoid duplicates across subs
    seen = set()

    try:
        for sub in sub_client.subscriptions.list():
            sub_id = sub.subscription_id
            ctx.info(f"Scanning subscription: {sub.display_name}...")
            
            auth_client = AuthorizationManagementClient(ctx.session, sub_id)
            # Filter for Owners (8e3af657...) and Contributors (b24988ac...)
            # and User Access Admins (18d7d81d...)
            HIGH_VALUE_ROLES = {
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
                "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
                "18d7d81d-424b-4813-a006-27c0ad510ed2": "User Access Administrator"
            }

            for assignment in auth_client.role_assignments.list_for_subscription():
                role_id = assignment.role_definition_id.split("/")[-1]
                
                if role_id in HIGH_VALUE_ROLES:
                    pname = assignment.principal_name or assignment.principal_id
                    key = f"{pname}-{role_id}"
                    if key not in seen:
                        admins.append({
                            "principal": pname,
                            "type": assignment.principal_type or "Unknown",
                            "role": HIGH_VALUE_ROLES[role_id],
                            "reason": f"Subscription-level Control ({sub.display_name})"
                        })
                        seen.add(key)
    except Exception as e:
        ctx.debug(f"Azure RBAC scan failed: {e}")

    return {"status": "success", "admins": admins}

# ================================================================
# GCP — Project-level Owner/Editor Discovery
# ================================================================

def _enum_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return {"error": "GCP SDK not installed."}

    admins = []
    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    
    # We probe the current project from the whoami context
    whoami = ctx.whoami()
    project_id = whoami.account_id
    
    if not project_id or project_id == "unknown":
        return {"error": "No GCP project identified."}

    try:
        req = {"resource": f"projects/{project_id}"}
        policy = client.get_iam_policy(request=req)

        # Obvious Admin Roles
        ADMIN_ROLES = ["roles/owner", "roles/editor"]

        for binding in policy.bindings:
            if binding.role in ADMIN_ROLES:
                for member in binding.members:
                    # e.g. user:moses@acme.com -> moses@acme.com
                    name = member.split(":", 1)[-1] if ":" in member else member
                    mtype = member.split(":", 1)[0].title() if ":" in member else "Unknown"
                    
                    admins.append({
                        "principal": name,
                        "type": mtype,
                        "role": binding.role,
                        "reason": f"Project-wide {binding.role.split('/')[-1]} rights"
                    })
    except Exception as e:
        ctx.debug(f"GCP IAM scan failed for {project_id}: {e}")

    return {"status": "success", "admins": admins}

# ================================================================
# OCI — Tenancy Administrator Discovery
# ================================================================

def _enum_oci(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        import oci
    except ImportError:
        return {"error": "OCI SDK not installed."}

    admins = []
    config = ctx.session["config"]
    signer = ctx.session.get("signer")
    
    identity = oci.identity.IdentityClient(config, signer=signer) if signer else oci.identity.IdentityClient(config)
    tenancy_id = config.get("tenancy")

    try:
        # 1. Identify the 'Administrators' group (built-in)
        groups = identity.list_groups(tenancy_id).data
        admin_group = next((g for g in groups if g.name == "Administrators"), None)
        
        if admin_group:
            memberships = identity.list_user_group_memberships(tenancy_id, group_id=admin_group.id).data
            for m in memberships:
                user = identity.get_user(m.user_id).data
                admins.append({
                    "principal": user.name,
                    "type": "User",
                    "role": "Administrators Group",
                    "reason": "Full Tenancy Control (Built-in Group)"
                })
    except Exception as e:
        ctx.debug(f"OCI Admin scan failed: {e}")

    return {"status": "success", "admins": admins}

# ================================================================
# Entra ID — delegate to entra_enum_privileged_roles (authoritative)
# ================================================================

from quantum_mechanic.techniques.discovery import entra_enum_privileged_roles

def _enum_entra(ctx: ExecutionContext) -> dict[str, Any]:
    result = entra_enum_privileged_roles.execute(ctx)
    if "error" in result:
        return {"status": "error", "error": result["error"], "admins": []}
    admins = [
        {
            "principal": a.get("principal_name", "—"),
            "type": a.get("principal_type", "—"),
            "role": a.get("role_name", "—"),
            "reason": f"{a.get('tier', '')} — {a.get('assignment_type', 'Permanent')}",
        }
        for a in result.get("assignments", [])
    ]
    return {"status": "success", "admins": admins}
