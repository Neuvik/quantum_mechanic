# ================================================================
# TECHNIQUE: discovery/enum_iam
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087 — Account Discovery
#
# PURPOSE:   Identify the exact permissions and policies attached
#            to the active principal.
#
# PROVIDERS: AWS (Azure, GCP, OCI pending)
#
# HOW IT WORKS:
#   AWS   — If User: Calls ListAttachedUserPolicies, ListUserPolicies,
#           and GetPolicyVersion to dump exact statement JSONs.
#           If Role: Calls ListAttachedRolePolicies, ListRolePolicies,
#           and GetPolicyVersion logic.
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: ListAttachedUserPolicies, GetPolicyVersion, etc.
#           Alert on: High volumes of IAM Get/List calls from a
#           single identity within a short timeframe (enumeration).
#
# SAFE:     Yes — completely read-only, no state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

try:
    from azure.mgmt.authorization import AuthorizationManagementClient
except ImportError:
    AuthorizationManagementClient = None

try:
    from google.cloud import resourcemanager_v3
except ImportError:
    resourcemanager_v3 = None

logger = logging.getLogger(__name__)


@technique(
    technique_id="discovery/enum_iam",
    tactic="Discovery",
    mitre_id="T1087.004",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Enumerate IAM policies and permissions attached to the active principal.",
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
        "principal": whoami_res.friendly_name,
        "principal_type": whoami_res.principal_type,
        "project_roles": roles_found,
    }


def _enum_oci(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate OCI IAM policies for the current principal."""
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

    # 2. Extract policy statements for the tenancy
    # We only pull tenancy-level policies here for MVP.
    # Sub-compartment policies require recursive enumeration.
    try:
        tenancy_policies = identity_client.list_policies(compartment_id=tenancy_id).data

        for p in tenancy_policies:
            policies.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "statements": p.statements,
                }
            )
    except Exception as e:
        msg = getattr(e, "message", str(e))
        logger.warning(f"Failed to list tenancy policies: {msg}")

    return {
        "status": "success",
        "principal": friendly_name,
        "principal_type": whoami_res.principal_type,
        "groups": groups,
        "tenancy_policies": policies,
    }
