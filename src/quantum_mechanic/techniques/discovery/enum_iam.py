# ================================================================
# TECHNIQUE: discovery/enum_iam
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087 — Account Discovery
#
# PURPOSE:   Identify the exact permissions and policies attached
#            to the active principal.
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — If User: Calls ListAttachedUserPolicies, ListUserPolicies,
#           and GetPolicyVersion to dump exact statement JSONs.
#           If Role: Calls ListAttachedRolePolicies, ListRolePolicies,
#           and GetPolicyVersion logic.
#
#   Azure — Enumerates Role Assignments for the current principal's
#           object ID across all accessible subscriptions.
#
#   GCP   — Searches for accessible projects and calls getIamPolicy
#           on each to identify roles assigned to the current
#           Service Account or User.
#
#   OCI   — Lists user group memberships and recursively enumerates
#           all policies in all compartments within the tenancy.
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: ListAttachedUserPolicies, GetPolicyVersion, etc.
#           Alert on: High volumes of IAM Get/List calls from a
#           single identity within a short timeframe (enumeration).
#
#   Azure — Monitor: RoleAssignments/read. Look for enumeration
#           of RBAC across multiple subscriptions.
#
#   GCP   — Audit Logs: getIamPolicy. Monitor for rapid role
#           checks across multiple project IDs.
#
#   OCI   — Audit Service: ListPolicies, ListUserGroupMemberships.
#           Monitor for recursive policy listing.
#
# SAFE:     Yes — completely read-only, no state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — CloudFox-style output (loot.csv / table.txt)
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'attached_policies'
LOOT_SCHEMA = [
    ('PolicyName', 'PolicyName'),
    ('PolicyArn', 'PolicyArn'),
]

try:
    from azure.mgmt.authorization import AuthorizationManagementClient
except ImportError:
    AuthorizationManagementClient = None

try:
    from google.cloud import resourcemanager_v3
except ImportError:
    resourcemanager_v3 = None

logger = logging.getLogger(__name__)


def format_iam_result(result: Any) -> None:
    """Decentralized formatter for IAM enumeration."""
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    provider = result.provider
    principal = data.get("principal", "unknown")
    principal_type = data.get("principal_type", "unknown")

    console.print(f"  [bold green]✓[/bold green] IAM Enumeration for {provider.upper()} {principal_type} [cyan]{principal}[/cyan]")

    if provider == "aws":
        attached_policies = data.get("attached_policies", [])
        inline_policies = data.get("inline_policies", [])

        if not attached_policies and not inline_policies:
            console.print("  [dim]No attached or inline IAM policies found.[/dim]")
            return

        if attached_policies:
            table = Table(box=None, padding=(0, 2), title="Attached Managed Policies", title_style="bold cyan")
            table.add_column("Policy Name", style="white")
            table.add_column("Policy ARN", style="dim")
            for p in attached_policies:
                table.add_row(p.get("PolicyName", ""), p.get("PolicyArn", ""))
            console.print(table)

        if inline_policies:
            table = Table(box=None, padding=(0, 2), title="Inline Policies", title_style="bold yellow")
            table.add_column("Policy Name", style="white")
            for p in inline_policies:
                table.add_row(p.get("PolicyName", ""))
            console.print(table)

    elif provider == "azure":
        assignments = data.get("role_assignments", [])
        if not assignments:
            console.print("  [dim]No Azure role assignments found.[/dim]")
            return

        table = Table(box=None, padding=(0, 2), title="Azure Role Assignments", title_style="bold cyan")
        table.add_column("Role Name", style="bold white")
        table.add_column("Scope", style="dim")
        table.add_column("Definition ID", style="dim")
        for a in assignments:
            table.add_row(a.get("roleName", "Unknown"), a.get("scope", ""), str(a.get("roleDefinitionId", "")))
        console.print(table)

    elif provider == "gcp":
        roles = data.get("project_roles", [])
        if not roles:
            console.print("  [dim]No GCP IAM roles found.[/dim]")
            return

        table = Table(box=None, padding=(0, 2), title="GCP Project Roles", title_style="bold cyan")
        table.add_column("Project", style="bold white")
        table.add_column("Role", style="green")
        table.add_column("Condition", style="dim")
        for r in roles:
            condition = r.get("condition") or "None"
            table.add_row(r.get("project", ""), r.get("role", ""), str(condition))
        console.print(table)

    elif provider == "oci":
        groups = data.get("groups", [])
        policies = data.get("policies", [])

        if not groups and not policies:
            console.print("  [dim]No OCI groups or policies found.[/dim]")
            return

        if groups:
            table = Table(box=None, padding=(0, 2), title="OCI Group Memberships", title_style="bold cyan")
            table.add_column("Group Name", style="bold white")
            table.add_column("Group ID", style="dim")
            for g in groups:
                table.add_row(g.get("name", ""), g.get("id", ""))
            console.print(table)

        if policies:
            table = Table(box=None, padding=(0, 2), title="OCI Policies (Across Compartments)", title_style="bold yellow")
            table.add_column("Policy Name", style="bold white")
            table.add_column("Compartment", style="dim")
            table.add_column("Statements", style="green")
            for p in policies:
                statements = "\n".join(p.get("statements", []))
                table.add_row(p.get("name", ""), p.get("compartment_id", "tenancy"), statements)
            console.print(table)


@technique(
    technique_id="discovery/enum_iam",
    tactic='discovery',
    mitre_id="T1087.004",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Enumerate IAM policies and permissions attached to the active principal.",
    formatter=format_iam_result,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute the IAM enumeration technique.

    Args:
        ctx: Execution context with active credential and provider.

    Returns:
        Dictionary of attached policies and parsed permission statements.
    """
    if ctx.provider_name not in ("aws", "azure", "gcp", "oci"):
        return {
            "error": f"Provider {ctx.provider_name} not yet implemented for enum_iam.",
            "policies": [],
        }

    # 1. We must know who we are to know what policies to query.
    whoami_res = ctx.whoami()
    if whoami_res.principal_type == "unknown":
        return {
            "error": "Could not determine principal type. Cannot enumerate IAM.",
            "policies": [],
        }

    if ctx.provider_name == "azure":
        return _enum_azure(ctx, whoami_res)

    if ctx.provider_name == "gcp":
        return _enum_gcp(ctx, whoami_res)

    if ctx.provider_name == "oci":
        return _enum_oci(ctx, whoami_res)

    iamv2 = ctx.session.client("iam")

    attached_policies = []
    inline_policies = []
    policy_documents = []

    # 2. Extract specific name
    # e.g. arn:aws:iam::123:user/morpheus -> morpheus
    friendly_name = whoami_res.friendly_name

    if ctx.provider_name == "aws":
        # Ensure we perfectly isolate the actual Username/RoleName entirely independent of pathing (e.g. testing/production/user -> user)
        friendly_name = friendly_name.split("/")[-1]

    try:
        if whoami_res.principal_type == "user":
            # Managed policies
            paginator = iamv2.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=friendly_name):
                for p in page.get("AttachedPolicies", []):
                    attached_policies.append(p)

            # Inline policies
            inline_paginator = iamv2.get_paginator("list_user_policies")
            for page in inline_paginator.paginate(UserName=friendly_name):
                for p in page.get("PolicyNames", []):
                    inline_policies.append({"PolicyName": p})
                    doc = iamv2.get_user_policy(UserName=friendly_name, PolicyName=p)
                    policy_documents.append(
                        {"Source": "inline", "PolicyName": p, "Document": doc.get("PolicyDocument")}
                    )

        elif whoami_res.principal_type in ("role", "assumed_role"):
            # Managed policies
            paginator = iamv2.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=friendly_name):
                for p in page.get("AttachedPolicies", []):
                    attached_policies.append(p)

            # Inline policies
            inline_paginator = iamv2.get_paginator("list_role_policies")
            for page in inline_paginator.paginate(RoleName=friendly_name):
                for p in page.get("PolicyNames", []):
                    inline_policies.append({"PolicyName": p})
                    doc = iamv2.get_role_policy(RoleName=friendly_name, PolicyName=p)
                    policy_documents.append(
                        {"Source": "inline", "PolicyName": p, "Document": doc.get("PolicyDocument")}
                    )
        else:
            return {
                "error": (
                    f"IAM enumeration not supported for principal type: {whoami_res.principal_type}"
                ),
                "policies": [],
            }

        # 3. Resolve managed policy documents
        for ap in attached_policies:
            arn = ap["PolicyArn"]
            try:
                pol = iamv2.get_policy(PolicyArn=arn)
                ver_id = pol.get("Policy", {}).get("DefaultVersionId")
                if ver_id:
                    ver = iamv2.get_policy_version(PolicyArn=arn, VersionId=ver_id)
                    policy_documents.append(
                        {
                            "Source": "managed",
                            "PolicyName": ap["PolicyName"],
                            "PolicyArn": arn,
                            "Document": ver.get("PolicyVersion", {}).get("Document"),
                        }
                    )
            except Exception as e:
                logger.warning(f"Could not fetch document for policy {arn}: {e}")

    except Exception as e:
        return {
            "error": f"IAM enumeration failed (often due to lack of permissions): {str(e)}",
            "attached_policies": attached_policies,
            "inline_policies": inline_policies,
            "policy_documents": policy_documents,
        }

    return {
        "status": "success",
        "principal": friendly_name,
        "principal_type": whoami_res.principal_type,
        "attached_policies": attached_policies,
        "inline_policies": inline_policies,
        "policy_documents": policy_documents,
    }


def _enum_azure(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate Azure RBAC assignments for the current principal."""
    if AuthorizationManagementClient is None:
        return {
            "status": "error",
            "error": "azure-mgmt-authorization package is not installed.",
            "principal": whoami_res.friendly_name,
            "principal_type": whoami_res.principal_type,
            "role_assignments": [],
        }

    principal_id = whoami_res.principal_id
    friendly_name = whoami_res.friendly_name

    assignments = []
    subscriptions = whoami_res.extra.get("subscriptions", [])

    if not subscriptions:
        return {
            "status": "error",
            "error": "No accessible subscriptions found. Cannot enumerate RBAC.",
            "principal": friendly_name,
            "principal_type": whoami_res.principal_type,
            "role_assignments": [],
        }

    for sub in subscriptions:
        sub_id = sub["id"]
        try:
            auth_client = AuthorizationManagementClient(ctx.session, sub_id)
            filter_str = f"principalId eq '{principal_id}'"

            for assignment in auth_client.role_assignments.list_for_subscription(filter=filter_str):
                role_def_id = assignment.role_definition_id
                role_name = "Unknown"

                try:
                    role_def = auth_client.role_definitions.get_by_id(role_def_id)
                    role_name = role_def.role_name
                except Exception as inner_e:
                    logger.warning(f"Failed to resolve role definition {role_def_id}: {inner_e}")

                assignments.append(
                    {
                        "id": assignment.id,
                        "scope": assignment.scope,
                        "roleDefinitionId": role_def_id,
                        "roleName": role_name,
                    }
                )
        except Exception as e:
            logger.warning(f"Could not list role assignments for subscription {sub_id}: {e}")

    return {
        "status": "success",
        "principal": friendly_name,
        "principal_type": whoami_res.principal_type,
        "role_assignments": assignments,
        # Loot schema compatibility: map role_assignments → attached_policies
        "attached_policies": [
            {"PolicyName": a.get("roleName", "Unknown"), "PolicyArn": a.get("scope", "")}
            for a in assignments
        ],
    }


def _enum_gcp(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate GCP IAM roles for the current principal."""
    if resourcemanager_v3 is None:
        return {
            "status": "error",
            "error": "google-cloud-resource-manager package is not installed.",
            "principal": whoami_res.friendly_name,
            "principal_type": whoami_res.principal_type,
            "project_roles": [],
        }

    principal_id = whoami_res.principal_id
    friendly_name = whoami_res.friendly_name
    member_str = f"user:{principal_id}"
    if whoami_res.principal_type == "service_account":
        member_str = f"serviceAccount:{principal_id}"

    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    projects = []

    try:
        for p in client.search_projects():
            projects.append(p.project_id)
    except Exception as e:
        logger.warning(f"Failed to search projects: {e}")
        if whoami_res.account_id and whoami_res.account_id != "unknown":
            projects.append(whoami_res.account_id)

    if not projects:
        return {
            "status": "error",
            "error": "No projects found and no default project available.",
            "principal": whoami_res.friendly_name,
            "principal_type": whoami_res.principal_type,
            "project_roles": [],
        }

    roles_found = []

    for pid in set(projects):
        try:
            req = {"resource": f"projects/{pid}"}
            policy = client.get_iam_policy(request=req)

            for binding in policy.bindings:
                if member_str in binding.members:
                    condition = None
                    if getattr(binding, "condition", None):
                        condition = getattr(binding.condition, "expression", None)
                    roles_found.append(
                        {
                            "project": pid,
                            "role": binding.role,
                            "condition": condition,
                        }
                    )
        except Exception as e:
            logger.warning(f"Could not get IAM policy for project {pid}: {e}")

    return {
        "status": "success",
        "principal": friendly_name,
        "principal_type": whoami_res.principal_type,
        "project_roles": roles_found,
    }


def _enum_oci(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate OCI IAM policies recursively across all compartments."""
    import oci

    config = ctx.session["config"]
    signer = ctx.session.get("signer")

    if signer:
        identity_client = oci.identity.IdentityClient(config={}, signer=signer)
    else:
        identity_client = oci.identity.IdentityClient(config)

    tenancy_id = whoami_res.tenant_id or whoami_res.account_id
    user_id = whoami_res.principal_id
    friendly_name = whoami_res.friendly_name

    if whoami_res.principal_type == "instance_principal":
        return {
            "error": "Instance Principal enumeration not fully supported yet.",
            "principal": friendly_name,
            "policies": [],
        }

    groups = []
    policies = []

    # 1. Get user group memberships
    try:
        memberships = identity_client.list_user_group_memberships(
            compartment_id=tenancy_id, user_id=user_id
        ).data

        for m in memberships:
            group_id = m.group_id
            try:
                g = identity_client.get_group(group_id).data
                groups.append({"id": g.id, "name": g.name})
            except Exception as e:
                msg = getattr(e, "message", str(e))
                logger.warning(f"Could not resolve group {group_id}: {msg}")
                groups.append({"id": group_id, "name": "unknown"})
    except Exception as e:
        msg = getattr(e, "message", str(e))
        logger.warning(f"Failed to list user group memberships: {msg}")

    # 2. Extract policy statements recursively across all compartments
    compartment_ids = [tenancy_id]
    try:
        # Fetch all child compartments recursively
        child_compartments = identity_client.list_compartments(
            tenancy_id, compartment_id_in_subtree=True, access_level="ACCESSIBLE"
        ).data
        compartment_ids.extend([c.id for c in child_compartments])
        ctx.info(f"Discovered {len(compartment_ids)} accessible compartments for policy enumeration.")
    except Exception as e:
        msg = getattr(e, "message", str(e))
        logger.warning(f"Failed to list child compartments: {msg}")

    for cid in compartment_ids:
        try:
            comp_policies = identity_client.list_policies(compartment_id=cid).data
            for p in comp_policies:
                policies.append(
                    {
                        "id": p.id,
                        "name": p.name,
                        "compartment_id": cid,
                        "statements": p.statements,
                    }
                )
        except Exception as e:
            msg = getattr(e, "message", str(e))
            logger.debug(f"Failed to list policies in compartment {cid}: {msg}")

    return {
        "status": "success",
        "principal": friendly_name,
        "principal_type": whoami_res.principal_type,
        "groups": groups,
        "policies": policies,
    }
