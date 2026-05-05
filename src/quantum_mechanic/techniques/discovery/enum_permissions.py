# ================================================================
# TECHNIQUE: discovery/enum_permissions
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1069 — Permission Groups Discovery
#
# PURPOSE:   Actively verify if the current principal can perform
#            specific, highly-sensitive actions (e.g., privilege
#            escalation primitives, compute abuse, etc). This is
#            more reliable than static policy analysis.
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — Attempts iam:SimulatePrincipalPolicy against a predefined
#           matrix of actions. If that is denied, falls back to
#           making actual API calls with the DryRun=True flag
#           where supported (e.g., EC2).
#   Azure — Not yet implemented.
#   GCP   — Not yet implemented.
#   OCI   — Not yet implemented.
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: SimulatePrincipalPolicy or a high volume of
#           UnauthorizedOperation or DryRunOperation errors.
#
# SAFE:     Yes — uses policy simulators or DryRun flags; no state is changed.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'permissions'
LOOT_SCHEMA = [
    ('action', 'Action', 'bold cyan'),
    ('status', 'Status', 'white'),
]

logger = logging.getLogger(__name__)


def format_permissions_result(result: Any) -> None:
    """Decentralized formatter for enum_permissions."""
    from rich.panel import Panel
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data

    if data.get("error"):
        console.print(f"  [bold red]✗[/bold red] {data['error']}")
        return

    provider = result.provider
    principal = data.get("principal", "unknown")
    method = data.get("method", "unknown")

    console.print(f"  [bold green]✓[/bold green] Permission Enumeration Successful — [dim]{provider.upper()}[/dim]")
    console.print(f"  [dim]Principal: [cyan]{principal}[/cyan] | Method: [yellow]{method}[/yellow][/dim]")

    allowed = data.get("allowed_actions", [])
    denied = data.get("denied_actions", [])

    if not allowed and not denied:
        console.print("  [dim]No specific actions tested or found.[/dim]")
        return

    tbl = Table(box=None, padding=(0, 2))
    tbl.add_column("Action", style="bold cyan")
    tbl.add_column("Status", justify="left")

    for a in allowed:
        tbl.add_row(a, "[bold green]ALLOWED[/bold green]")

    for a in denied:
        tbl.add_row(a, "[dim red]DENIED[/dim red]")

    console.print(Panel(tbl, border_style="dim", expand=False))

    if data.get("next_steps"):
        console.print("\n  [bold yellow]Next Steps:[/bold yellow]")
        for step in data["next_steps"]:
            console.print(f"    • {step}")


@technique(
    technique_id="discovery/enum_permissions",
    tactic='discovery',
    mitre_id="T1087",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Actively enumerate effective permissions for high-value actions.",
    formatter=format_permissions_result,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute the permissions enumeration technique.

    Args:
        ctx: Execution context with active credential and provider.

    Returns:
        Dictionary mapping sensitive actions to True, False, or Unknown.
    """
    if ctx.provider_name not in ("aws", "azure", "gcp", "oci"):
        return {
            "error": f"Provider {ctx.provider_name} not yet implemented for enum_permissions.",
            "allowed_actions": [],
            "denied_actions": [],
        }

    # 1. We must know who we are to simulate permissions
    whoami_res = ctx.whoami()
    if whoami_res.principal_type == "unknown":
        return {
            "error": "Could not determine principal. Cannot enumerate Permissions.",
            "allowed_actions": [],
            "denied_actions": [],
        }

    if ctx.provider_name == "aws":
        result = _enum_aws(ctx, whoami_res)
    elif ctx.provider_name == "azure":
        result = _enum_azure(ctx, whoami_res)
    elif ctx.provider_name == "gcp":
        result = _enum_gcp(ctx, whoami_res)
    elif ctx.provider_name == "oci":
        result = _enum_oci(ctx, whoami_res)
    else:
        result = {
            "error": f"Provider {ctx.provider_name} not yet implemented.",
        }

    # Analyze discovered permissions to generate actionable guidance
    if "allowed_actions" in result and getattr(result, "get", lambda x: None)("status") == "success":
        steps = _generate_next_steps(ctx.provider_name, result.get("allowed_actions", []))
        if steps:
            result["next_steps"] = steps

    return result


def _enum_aws(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate AWS permissions using IAM Policy Simulator and DryRuns."""

    # High-value targets for QM v1
    ACTIONS_TO_TEST = [
        "iam:PassRole",
        "sts:AssumeRole",
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ssm:SendCommand",
        "s3:ListAllMyBuckets",
        "secretsmanager:ListSecrets",
        "iam:CreateUser",
        "iam:CreateAccessKey"
    ]

    allowed = []
    denied = []
    errors = []

    arn = whoami_res.principal_id

    iamv2 = ctx.session.client("iam")

    # Approach 1: Try IAM Policy Simulator natively
    try:
        paginator = iamv2.get_paginator("simulate_principal_policy")
        for page in paginator.paginate(PolicySourceArn=arn, ActionNames=ACTIONS_TO_TEST):
            for result in page.get("EvaluationResults", []):
                action = result.get("EvalActionName")
                decision = result.get("EvalDecision")

                if decision == "allowed":
                    allowed.append(action)
                elif decision in ("implicitDeny", "explicitDeny"):
                    denied.append(action)
                else:
                    errors.append(f"{action}: {decision}")

        return {
            "status": "success",
            "method": "iam:SimulatePrincipalPolicy",
            "principal": arn,
            "allowed_actions": sorted(allowed),
            "denied_actions": sorted(denied),
            "errors": errors
        }

    except Exception as e:
        logger.debug(f"iam:SimulatePrincipalPolicy failed or denied: {e}. Falling back to active probing/DryRun.")

    # Approach 2: Active API Call Probing / DryRun Fallback
    # If we lack permission to use the simulator, we must actively check the endpoints.
    # Note: Not all AWS actions support DryRun. For simplicity in the MVP, we will only DryRun what we can.

    active_allowed = []
    active_denied = []
    active_errors = []

    ec2_client = ctx.session.client("ec2")
    try:
        # Check ec2:DescribeInstances
        ec2_client.describe_instances(DryRun=True)
    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "DryRunOperation":
            active_allowed.append("ec2:DescribeInstances")
        elif error_code == "UnauthorizedOperation":
            active_denied.append("ec2:DescribeInstances")
        else:
            active_errors.append(f"ec2:DescribeInstances unknown error: {str(e)}")

    try:
        # Check ec2:RunInstances (basic check, no parameters means it might fail on MissingParameter, but we can check UnauthorizedOperation first)
        ec2_client.run_instances(DryRun=True, MaxCount=1, MinCount=1)
    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        # Even if MissingParameter, an UnauthorizedOperation usually supersedes it if permissions are totally missing.
        # But if it's DryRunOperation, we have permission to RunInstances at a baseline.
        if error_code == "DryRunOperation" or "MissingParameter" in str(e):
            # MissingParameter implies we got past authz but failed validation. We'll tentatively assume Allowed.
            active_allowed.append("ec2:RunInstances")
        elif error_code == "UnauthorizedOperation":
            active_denied.append("ec2:RunInstances")
        else:
            active_errors.append(f"ec2:RunInstances check failed: {str(e)}")

    return {
        "status": "success",
        "method": "active_dryrun_fallback",
        "principal": arn,
        "allowed_actions": sorted(active_allowed),
        "denied_actions": sorted(active_denied),
        "errors": active_errors,
        "note": "Simulator access denied. Fell back to partial DryRun probing. Results are incomplete."
    }


def _enum_azure(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate Azure effective permissions using Authorization API."""
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
    except ImportError:
        return {
            "status": "error",
            "error": "azure-mgmt-authorization package is not installed.",
            "principal": whoami_res.friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    friendly_name = whoami_res.friendly_name
    subscriptions = whoami_res.extra.get("subscriptions", [])

    if not subscriptions:
        return {
            "status": "error",
            "error": "No accessible subscriptions found. Cannot enumerate permissions.",
            "principal": friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    allowed_actions = set()
    not_actions = set()
    data_actions = set()
    not_data_actions = set()
    errors = []

    for sub in subscriptions:
        sub_id = sub["id"]
        try:
            auth_client = AuthorizationManagementClient(ctx.session, sub_id)

            # This API calculates the caller's effective permissions for the given subscription.
            sub_permissions = auth_client.permissions.list_for_subscription()

            for perm in sub_permissions:
                if perm.actions:
                    allowed_actions.update(perm.actions)
                if perm.not_actions:
                    not_actions.update(perm.not_actions)
                if perm.data_actions:
                    data_actions.update(perm.data_actions)
                if perm.not_data_actions:
                    not_data_actions.update(perm.not_data_actions)

        except Exception as e:
            msg = getattr(e, "message", str(e))
            logger.warning(f"Could not list permissions for subscription {sub_id}: {msg}")
            errors.append(f"Sub {sub_id}: {msg}")

    return {
        "status": "success",
        "method": "AuthorizationManagementClient.permissions.list_for_subscription",
        "principal": friendly_name,
        "allowed_actions": sorted(list(allowed_actions)),
        "denied_actions": sorted(list(not_actions)),
        "data_actions": sorted(list(data_actions)),
        "denied_data_actions": sorted(list(not_data_actions)),
        "errors": errors
    }


def _enum_gcp(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate GCP permissions using TestIamPermissions API on accessible projects."""
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        return {
            "status": "error",
            "error": "google-cloud-resource-manager package is not installed.",
            "principal": whoami_res.friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    ACTIONS_TO_TEST = [
        "iam.serviceAccounts.actAs",
        "iam.serviceAccountKeys.create",
        "compute.instances.create",
        "compute.instances.osLogin",
        "compute.instances.setMetadata",
        "storage.buckets.list",
        "storage.objects.get",
        "resourcemanager.projects.getIamPolicy"
    ]

    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    projects = []

    # Identify accessible projects (same logic used in enum_iam)
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
            "error": "No accessible projects found. Cannot test permissions.",
            "principal": whoami_res.friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    # GCP test_iam_permissions only returns what is ALLOWED.
    # What is not in the response is assumed DENIED.
    allowed_actions = set()
    denied_actions = set()
    errors = []

    for pid in set(projects):
        try:
            req = {
                "resource": f"projects/{pid}",
                "permissions": ACTIONS_TO_TEST
            }
            response = client.test_iam_permissions(request=req)

            perms = response.permissions if hasattr(response, "permissions") else response.get("permissions", [])
            for action in ACTIONS_TO_TEST:
                if action in perms:
                    allowed_actions.add(action)
                else:
                    denied_actions.add(action)
        except Exception as e:
            msg = getattr(e, "message", str(e))
            logger.warning(f"Could not test IAM permissions on project {pid}: {msg}")
            errors.append(f"Project {pid}: {msg}")

    return {
        "status": "success",
        "method": "resourcemanager_v3.ProjectsClient.test_iam_permissions",
        "principal": whoami_res.friendly_name,
        "allowed_actions": sorted(list(allowed_actions)),
        "denied_actions": sorted(list(denied_actions)),
        "errors": errors
    }


def _enum_oci(ctx: ExecutionContext, whoami_res: Any) -> dict[str, Any]:
    """Enumerate OCI permissions via active probing."""
    try:
        import oci
    except ImportError:
        return {
            "status": "error",
            "error": "oci package is not installed.",
            "principal": whoami_res.friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    config = ctx.session["config"]
    signer = ctx.session.get("signer")

    tenancy_id = config.get("tenancy")
    if not tenancy_id:
        return {
            "status": "error",
            "error": "Could not determine tenancy OCID from config.",
            "principal": whoami_res.friendly_name,
            "allowed_actions": [],
            "denied_actions": [],
        }

    if signer:
        identity = oci.identity.IdentityClient(config={}, signer=signer)
        compute = oci.core.ComputeClient(config={}, signer=signer)
        vcn = oci.core.VirtualNetworkClient(config={}, signer=signer)
    else:
        identity = oci.identity.IdentityClient(config)
        compute = oci.core.ComputeClient(config)
        vcn = oci.core.VirtualNetworkClient(config)

    allowed_actions = []
    denied_actions = []
    errors = []

    def probe(action_name: str, client_obj: Any, method_name: str, **kwargs: Any) -> None:
        try:
            method = getattr(client_obj, method_name)
            method(**kwargs)
            allowed_actions.append(action_name)
        except oci.exceptions.ServiceError as e:
            if getattr(e, "status", None) == 404 and "NotAuthorizedOrNotFound" in getattr(e, "message", "") or getattr(e, "status", None) == 401:
                denied_actions.append(action_name)
            else:
                errors.append(f"{action_name}: {getattr(e, 'message', str(e))}")
        except Exception as e:
            errors.append(f"{action_name}: {str(e)}")

    probe("identity:list_users", identity, "list_users", compartment_id=tenancy_id, limit=1)
    probe("identity:list_groups", identity, "list_groups", compartment_id=tenancy_id, limit=1)
    probe("compute:list_instances", compute, "list_instances", compartment_id=tenancy_id, limit=1)
    probe("virtual_network:list_vcns", vcn, "list_vcns", compartment_id=tenancy_id, limit=1)

    # Optional: Object Storage namespace and buckets
    try:
        if signer:
            os_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        else:
            os_client = oci.object_storage.ObjectStorageClient(config)

        ns = os_client.get_namespace().data
        probe(
            "object_storage:list_buckets",
            os_client,
            "list_buckets",
            namespace_name=ns,
            compartment_id=tenancy_id,
            limit=1
        )
    except Exception as e:
        denied_actions.append("object_storage:get_namespace")
        errors.append(f"object_storage init: {str(e)}")

    return {
        "status": "success",
        "method": "active_probing_list_apis",
        "principal": whoami_res.friendly_name,
        "allowed_actions": sorted(allowed_actions),
        "denied_actions": sorted(denied_actions),
        "errors": errors,
    }


def _generate_next_steps(provider: str, allowed: list[str]) -> list[str]:
    """Correlate allowed permissions with actionable Quantum Mechanic techniques."""
    steps = []

    if provider == "aws":
        if "iam:PassRole" in allowed and "ec2:RunInstances" in allowed:
            steps.append("You have ec2:RunInstances and iam:PassRole. Use 'escalation/compute_identity_abuse' to launch an EC2 instance and steal target IAM roles via IMDS.")
        if "sts:AssumeRole" in allowed:
            steps.append("You can assume other roles. Use 'escalation/assume_role_chain' to scan for accessible roles.")
        if "ssm:SendCommand" in allowed:
            steps.append("You can execute commands on EC2 instances. Check for managed instances and use SSM to gain RCE.")

    elif provider == "azure":
        # Note: action strings from ARM are usually exact or wildcard matched.
        # We check substring to be safe with Azure's permission string casing.
        allowed_lower = [a.lower() for a in allowed]

        if any("runcommand/action" in a for a in allowed_lower):
            steps.append("You can execute code on Virtual Machines. Use 'lateral_movement/vm_execute_command' to gain RCE on targets.")
        if any("roleassignments/write" in a for a in allowed_lower):
            steps.append("You have RBAC write access. You can assign yourself or others Highly Privileged roles (e.g., Owner/Contributor).")
        if any("managedidentities/assign/action" in a for a in allowed_lower) and any("virtualmachines/write" in a for a in allowed_lower):
            steps.append("You can attach Managed Identities to VMs. Use 'escalation/compute_identity_abuse' to steal their access tokens.")

    elif provider == "gcp":
        if "iam.serviceAccounts.actAs" in allowed and "compute.instances.create" in allowed:
            steps.append("You can launch Compute Engine instances with Service Accounts. Use 'escalation/compute_identity_abuse' to harvest their tokens.")
        if "iam.serviceAccountKeys.create" in allowed:
            steps.append("You can generate new keys for Service Accounts. Use 'escalation/gcp_sa_token_creator'.")
        if "compute.instances.osLogin" in allowed:
            steps.append("You can log into instances using OS Login. Generate an ephemeral SSH key and authenticate to target instances.")

    # Generic fallback if no specific primitives matched, but they have access
    if not steps and allowed:
        steps.append("Review the 'allowed_actions' list for native management console or CLI exploitation paths.")

    return steps
