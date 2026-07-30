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
#   Azure — Calls ComputeManagementClient.virtual_machines.list_all()
#           and surfaces VM metadata (including Managed Identities).
#   GCP   — Calls instances().aggregatedList() and surfaces all VMs.
#           Default compute SAs are flagged if attached.
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

import json
import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'instances'
LOOT_SCHEMA = [
    ('instance_id', 'Instance ID', 'bold cyan'),
    ('state',       'State',       'dim'),
    ('os_type',     'OS',          'dim'),
    ('type',        'Type',        'dim'),
    ('private_ip',  'Private IP',  'white'),
    ('public_ip',   'Public IP',   'white'),
    ('identity',    'Identity',    'yellow'),
    ('region',      'Region',      'dim'),
    ('vm_id',       'Resource ID', 'dim'),
]

logger = logging.getLogger(__name__)


@technique(
    technique_id="discovery/enum_compute",
    tactic='discovery',
    mitre_id="T1580",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="List all compute instances and optionally retrieve their assigned metadata.",
    parameters=[
        Parameter("project", "Target GCP project ID (override default)", required=False)
    ],
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
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
    """List EC2 instances and retrieve their assigned metadata.

    ctx.session is a boto3.Session already authenticated by the AWS provider.
    """
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return {"error": "boto3 not installed.", "instances": []}

    try:
        ec2 = ctx.session.client("ec2")

        try:
            regions_resp = ec2.describe_regions()
            regions = [r["RegionName"] for r in regions_resp.get("Regions", [])]
        except (BotoCoreError, ClientError):
            regions = ["us-east-1"]

        instances = []
        for region in regions:
            try:
                regional_ec2 = ctx.session.client("ec2", region_name=region)
                paginator = regional_ec2.get_paginator("describe_instances")

                for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for inst in reservation.get("Instances", []):
                            profile = inst.get("IamInstanceProfile")
                            instances.append({
                                "instance_id": inst.get("InstanceId"),
                                "vm_id": inst.get("InstanceId"),
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
                                "identity": profile.get("Arn").split("/")[-1] if profile and profile.get("Arn") else None,
                                "instance_profile_arn": profile.get("Arn") if profile else None,
                                "instance_profile_id": profile.get("Id") if profile else None,
                                "image_id": inst.get("ImageId"),
                                "region": region,
                            })
            except ClientError as e:
                logger.debug("Skipping AWS region %s for enum_compute: %s", region, e)

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
    """List Azure VMs and retrieve their assigned metadata.

    ctx.session is a TokenCredential already authenticated by the Azure provider.
    """
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-compute not installed.", "instances": []}

    try:
        from azure.mgmt.network import NetworkManagementClient as _NetworkClient
    except ImportError:
        _NetworkClient = None

    try:
        cred = ctx.session

        ctx.info("Azure: enumerating VMs — this may take a minute (one API call per VM for power state).")

        sub_client = SubscriptionClient(cred)
        subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]

        instances = []
        for sub_id in subscriptions:
            compute = ComputeManagementClient(cred, sub_id)
            network = _NetworkClient(cred, sub_id) if _NetworkClient else None

            for vm in compute.virtual_machines.list_all():
                identity = vm.identity

                user_assigned = {}
                if identity and identity.user_assigned_identities:
                    user_assigned = {
                        resource_id: {
                            "principal_id": info.principal_id,
                            "client_id": info.client_id,
                        }
                        for resource_id, info in identity.user_assigned_identities.items()
                    }

                id_type = (
                    identity.type.value if hasattr(identity.type, "value") else str(identity.type)
                ) if identity and getattr(identity, "type", None) else "None"

                identity_parts = [f"Type: {id_type}"]
                if user_assigned:
                    first_id = list(user_assigned.keys())[0].split("/")[-1]
                    identity_parts.append(f"UserID: {first_id}")
                if identity and getattr(identity, "principal_id", None):
                    identity_parts.append(f"SystemID: {identity.principal_id[:8]}...")

                # Fetch NIC IP data
                private_ip = None
                public_ip = None
                if vm.network_profile and vm.network_profile.network_interfaces:
                    for nic_ref in vm.network_profile.network_interfaces:
                        try:
                            nic_parts = (nic_ref.id or "").split("/")
                            nic_rg = nic_parts[nic_parts.index("resourceGroups") + 1]
                            nic_name = nic_parts[-1]
                            nic = network.network_interfaces.get(nic_rg, nic_name)
                            for ip_cfg in (nic.ip_configurations or []):
                                if not private_ip:
                                    private_ip = ip_cfg.private_ip_address
                                if not public_ip and ip_cfg.public_ip_address:
                                    try:
                                        pip_parts = ip_cfg.public_ip_address.id.split("/")
                                        pip_rg = pip_parts[pip_parts.index("resourceGroups") + 1]
                                        pip_name = pip_parts[-1]
                                        pip = network.public_ip_addresses.get(pip_rg, pip_name)
                                        public_ip = pip.ip_address
                                    except Exception:
                                        pass
                        except Exception as nic_err:
                            logger.debug("Failed to get NIC data for %s: %s", vm.name, nic_err)

                # Power state requires instance_view (extra call per VM)
                power_state = "unknown"
                try:
                    vm_parts = (vm.id or "").lstrip("/").split("/")
                    vm_rg = vm_parts[vm_parts.index("resourceGroups") + 1]
                    iv = compute.virtual_machines.instance_view(vm_rg, vm.name)
                    for status in (iv.statuses or []):
                        if status.code and status.code.startswith("PowerState/"):
                            power_state = status.code.split("/", 1)[1]
                            break
                except Exception:
                    pass

                os_disk = getattr(vm.storage_profile, "os_disk", None) if vm.storage_profile else None
                raw_os = getattr(os_disk, "os_type", None)
                os_type = str(raw_os.value if hasattr(raw_os, "value") else raw_os or "unknown")

                instances.append({
                    "instance_id": vm.name,
                    "vm_id": vm.id,
                    "state": power_state,
                    "os_type": os_type,
                    "type": vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
                    "location": vm.location,
                    "region": vm.location,
                    "private_ip": private_ip,
                    "public_ip": public_ip,
                    "subscription_id": sub_id,
                    "identity": " | ".join(identity_parts),
                    "identity_type": id_type,
                    "system_assigned_principal_id": identity.principal_id if identity else None,
                    "user_assigned_identities": user_assigned,
                })

                # Persist to workspace AssetStore so cross-technique queries
                # ("which VMs have MIs with privileged Graph perms?") work
                # without re-running enum_compute.
                _mi_metadata = {
                    "system_assigned_principal_id": identity.principal_id if identity else None,
                    "user_assigned_identities": user_assigned,
                    "identity_type": id_type,
                }
                try:
                    ctx.workspace.upsert_compute_instance(
                        provider="azure",
                        instance_id=vm.name,
                        name=vm.name,
                        state=power_state,
                        instance_type=vm.hardware_profile.vm_size if vm.hardware_profile else None,
                        private_ip=private_ip,
                        public_ip=public_ip,
                        identity_arn=identity.principal_id if identity else None,
                        metadata=json.dumps(_mi_metadata),
                    )
                except Exception as _persist_err:
                    logger.warning(
                        "Workspace persistence for VM %s failed: %s (%s)",
                        vm.name, _persist_err, type(_persist_err).__name__,
                    )

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
    """List GCP Compute instances and retrieve their assigned metadata.

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
        project = ctx.get_param("project") or whoami.account_id

        if not project:
            return {"error": "Could not determine GCP project ID from credentials.", "instances": []}

        compute = build("compute", "v1", credentials=credentials)
        result = compute.instances().aggregatedList(project=project).execute()

        instances = []
        for zone_data in result.get("items", {}).values():
            for inst in zone_data.get("instances", []):
                service_accounts = inst.get("serviceAccounts", [])

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
                    "instance_id": inst.get("name"),
                    "vm_id": inst.get("name"),
                    "name": inst.get("name"),
                    "zone": inst.get("zone", "").split("/")[-1],
                    "region": inst.get("zone", "").split("/")[-1],
                    "state": inst.get("status"),
                    "type": inst.get("machineType", "").split("/")[-1],
                    "identity": ", ".join([sa["email"].split("@")[0] for sa in annotated_sas]) if annotated_sas else "None",
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
                        "instance_id": inst.display_name,
                        "vm_id": inst.id,
                        "ocid": inst.id,
                        "display_name": inst.display_name,
                        "compartment_id": inst.compartment_id,
                        "state": inst.lifecycle_state,
                        "type": inst.shape,
                        "identity": "Instance Principal (Dynamic Group Coverage)",
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
