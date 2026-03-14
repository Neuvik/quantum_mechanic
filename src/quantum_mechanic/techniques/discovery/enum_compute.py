# ================================================================
# TECHNIQUE: discovery/enum_compute
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   List compute instances and their attached identity
#            sources (Instance Profiles, Managed Identities,
#            Service Accounts).
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — ec2:DescribeInstances. Returns instance IDs, their
#           IamInstanceProfile ARNs, key names, and subnet IDs.
#           Only instances with an instance profile are returned.
#   Azure — Calls ComputeManagementClient.virtual_machines.list_all()
#           and surfaces any VM with a Managed Identity attached
#           (system-assigned or user-assigned).
#   GCP   — Calls instances().aggregatedList() and surfaces all VMs
#           that have any service account attached. Default compute
#           SAs are flagged since they are frequently Editor-level.
#   OCI   — Lists compute instances across all compartments. Also
#           lists Dynamic Groups so operators can correlate which
#           instances have instance-principal access.
#
# SESSION CONTRACT (ctx.session type per provider):
#   AWS   — boto3.Session (already authenticated)
#   Azure — azure.identity TokenCredential
#   GCP   — google.auth.credentials.Credentials
#   OCI   — dict with 'config' key and optional 'signer' key
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: ec2:DescribeInstances
#   Azure — Azure Monitor: Microsoft.Compute/virtualMachines/read
#   GCP   — Cloud Audit Logs: compute.instances.list
#   OCI   — OCI Audit: ListInstances
#
# SAFE:     Yes — completely read-only, no state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)


@technique(
    technique_id="discovery/enum_compute",
    tactic="Discovery",
    mitre_id="T1580",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="List compute instances and their attached cloud identities.",
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute compute enumeration across cloud providers.

    Args:
        ctx: Execution context with active credential and provider.

    Returns:
        Dictionary of compute instances with attached identity ARNs/IDs.
    """
    dispatch = {
        "aws": _enum_aws,
        "azure": _enum_azure,
        "gcp": _enum_gcp,
        "oci": _enum_oci,
    }
    handler = dispatch.get(ctx.provider_name)
    if handler is None:
        return {
            "error": f"Provider '{ctx.provider_name}' not implemented for enum_compute.",
            "instances": [],
        }
    return handler(ctx)


# ================================================================
# AWS — ec2:DescribeInstances
# ================================================================

def _enum_aws(ctx: ExecutionContext) -> dict[str, Any]:
    """List EC2 instances that have an IAM Instance Profile attached.

    ctx.session is a boto3.Session already authenticated by the AWS provider.
    """
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return {"error": "boto3 not installed.", "instances": []}

    try:
        ec2 = ctx.session.client("ec2")

        paginator = ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    profile = inst.get("IamInstanceProfile")
                    if not profile:
                        continue
                    instances.append({
                        "instance_id": inst.get("InstanceId"),
                        "state": inst.get("State", {}).get("Name"),
                        "type": inst.get("InstanceType"),
                        "key_name": inst.get("KeyName"),
                        "subnet_id": inst.get("SubnetId"),
                        "security_group_ids": [
                            sg["GroupId"]
                            for sg in inst.get("SecurityGroups", [])
                        ],
                        "private_ip": inst.get("PrivateIpAddress"),
                        "public_ip": inst.get("PublicIpAddress"),
                        "instance_profile_arn": profile.get("Arn"),
                        "instance_profile_id": profile.get("Id"),
                        "image_id": inst.get("ImageId"),
                    })

        return {
            "provider": "aws",
            "instances": instances,
            "total": len(instances),
        }

    except (BotoCoreError, ClientError) as e:
        logger.error("AWS enum_compute failed: %s", e)
        return {"error": str(e), "instances": []}


# ================================================================
# Azure — VirtualMachines.list_all()
# ================================================================

def _enum_azure(ctx: ExecutionContext) -> dict[str, Any]:
    """List Azure VMs that have a Managed Identity attached.

    ctx.session is a TokenCredential already authenticated by the Azure provider.
    """
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-compute not installed.", "instances": []}

    try:
        cred = ctx.session

        sub_client = SubscriptionClient(cred)
        subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]

        instances = []
        for sub_id in subscriptions:
            compute = ComputeManagementClient(cred, sub_id)
            for vm in compute.virtual_machines.list_all():
                identity = vm.identity
                if identity is None:
                    continue

                user_assigned = {}
                if identity.user_assigned_identities:
                    user_assigned = {
                        resource_id: {
                            "principal_id": info.principal_id,
                            "client_id": info.client_id,
                        }
                        for resource_id, info in identity.user_assigned_identities.items()
                    }

                instances.append({
                    "vm_id": vm.id,
                    "name": vm.name,
                    "location": vm.location,
                    "subscription_id": sub_id,
                    "identity_type": identity.type.value if identity.type else None,
                    "system_assigned_principal_id": identity.principal_id,
                    "user_assigned_identities": user_assigned,
                })

        return {
            "provider": "azure",
            "instances": instances,
            "total": len(instances),
        }

    except Exception as e:
        logger.error("Azure enum_compute failed: %s", e)
        return {"error": str(e), "instances": []}


# ================================================================
# GCP — compute.instances.aggregatedList()
# ================================================================

def _enum_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """List GCP Compute instances with service accounts.

    ctx.session is a google.auth.credentials.Credentials object already
    authenticated by the GCP provider. Project ID is derived from whoami.
    """
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed.", "instances": []}

    try:
        credentials = ctx.session
        whoami = ctx.whoami()
        project = whoami.account_id

        if not project:
            return {"error": "Could not determine GCP project ID from credentials.", "instances": []}

        compute = build("compute", "v1", credentials=credentials)
        result = compute.instances().aggregatedList(project=project).execute()

        instances = []
        for zone_data in result.get("items", {}).values():
            for inst in zone_data.get("instances", []):
                service_accounts = inst.get("serviceAccounts", [])
                if not service_accounts:
                    continue

                # Annotate each SA — the default compute SA is frequently
                # Editor-level and is just as dangerous as a custom one.
                annotated_sas = []
                for sa in service_accounts:
                    email = sa.get("email", "")
                    is_default = "developer.gserviceaccount.com" in email
                    annotated_sas.append({
                        "email": email,
                        "scopes": sa.get("scopes", []),
                        "is_default_compute_sa": is_default,
                        "risk_note": (
                            "Default Compute SA — often has project Editor rights."
                            if is_default
                            else "Custom SA — enumerate its IAM roles."
                        ),
                    })

                instances.append({
                    "instance_id": inst.get("id"),
                    "name": inst.get("name"),
                    "zone": inst.get("zone", "").split("/")[-1],
                    "status": inst.get("status"),
                    "machine_type": inst.get("machineType", "").split("/")[-1],
                    "service_accounts": annotated_sas,
                })

        return {
            "provider": "gcp",
            "instances": instances,
            "total": len(instances),
        }

    except Exception as e:
        logger.error("GCP enum_compute failed: %s", e)
        return {"error": str(e), "instances": []}


# ================================================================
# OCI — ComputeClient.list_instances()
# ================================================================

def _enum_oci(ctx: ExecutionContext) -> dict[str, Any]:
    """List OCI Compute instances.

    ctx.session is a dict with 'config' and optionally 'signer' keys,
    matching the OCI provider's authenticate() return value.
    """
    try:
        import oci
    except ImportError:
        return {"error": "oci not installed.", "instances": []}

    try:
        config = ctx.session["config"]
        signer = ctx.session.get("signer")

        if signer:
            identity = oci.identity.IdentityClient(config={}, signer=signer)
            compute_client = oci.core.ComputeClient(config={}, signer=signer)
        else:
            identity = oci.identity.IdentityClient(config)
            compute_client = oci.core.ComputeClient(config)

        tenancy_id = config.get("tenancy")
        compartment_ids = [tenancy_id]

        child_compartments = identity.list_compartments(
            tenancy_id, compartment_id_in_subtree=True
        ).data
        compartment_ids += [c.id for c in child_compartments]

        dynamic_groups = [
            {
                "id": dg.id,
                "name": dg.name,
                "matching_rule": dg.matching_rule,
            }
            for dg in identity.list_dynamic_groups(tenancy_id).data
        ]

        instances = []
        for cid in compartment_ids:
            try:
                for inst in compute_client.list_instances(compartment_id=cid).data:
                    if inst.lifecycle_state in ("TERMINATED", "TERMINATING"):
                        continue
                    instances.append({
                        "instance_id": inst.id,
                        "display_name": inst.display_name,
                        "compartment_id": inst.compartment_id,
                        "lifecycle_state": inst.lifecycle_state,
                        "shape": inst.shape,
                        "region": config.get("region"),
                    })
            except Exception as e:
                logger.debug("Skipping compartment %s (access denied or error): %s", cid, e)

        return {
            "provider": "oci",
            "instances": instances,
            "dynamic_groups": dynamic_groups,
            "total": len(instances),
        }

    except Exception as e:
        logger.error("OCI enum_compute failed: %s", e)
        return {"error": str(e), "instances": []}
