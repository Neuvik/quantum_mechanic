# ================================================================
# TECHNIQUE: discovery/enum_snapshots
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Enumerate EBS snapshots and AMIs owned by the account
#            and flag any that are publicly accessible. Public EBS
#            snapshots are a common misconfiguration — they allow any
#            AWS account to restore a full disk image, often containing
#            credentials, secrets, and sensitive application data.
#
# PROVIDERS: none required (unauthenticated) — uses active AWS credential
#            opportunistically when one is loaded.
#
# HOW IT WORKS:
#
#   Authenticated (active AWS credential present):
#     Audits YOUR account for misconfigurations.
#     ec2:DescribeSnapshots with OwnerIds=['self'] returns all snapshots
#     owned by the account. For each one, DescribeSnapshotAttribute with
#     Attribute='createVolumePermission' reveals if the snapshot has been
#     shared with Group=all (fully public).
#     ec2:DescribeImages with Owners=['self'] surfaces public AMIs you own.
#
#   Unauthenticated (no credential loaded):
#     External recon — finds public snapshots/AMIs in a TARGET account.
#     Uses anonymous boto3 calls (botocore UNSIGNED signature) to call:
#       DescribeSnapshots with RestorableByUserIds=['all']  — public snaps
#       DescribeImages    with ExecutableUsers=['all']      — public AMIs
#     Requires account_id or search to avoid returning the entire AWS
#     public snapshot corpus.
#
# REGION SCOPING:
#   region param controls which regions are scanned:
#     (not set)            — auto-detect enabled regions for this account
#                            via ec2:DescribeRegions (default, recommended)
#     region=us-east-1     — single region
#     region=us-east-1,us-east-2  — comma-separated list
#     region=all           — force all regions including opt-in ones
#
# DETECTION (Blue Team):
#   CloudTrail: DescribeSnapshots, DescribeSnapshotAttribute,
#               DescribeImages. Bulk attribute queries on snapshots
#               from an unknown identity are a strong signal.
#
# REFERENCES:
#   https://attack.mitre.org/techniques/T1580/
#   https://hackingthe.cloud/aws/enumeration/loot_public_ebs_snapshots/
#
# SAFE:     Yes — read-only, no state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import boto3

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = "snapshots"
LOOT_SCHEMA = [
    ("resource_id",   "Resource ID",   "bold cyan"),
    ("type",          "Type",          "dim"),
    ("description",   "Description",   "dim"),
    ("state",         "State",         "dim"),
    ("size_gb",       "Size (GB)",     "dim"),
    ("encrypted",     "Encrypted",     "dim"),
    ("public",        "Public",        "bold red"),
    ("region",        "Region",        "dim"),
    ("start_time",    "Created",       "dim"),
]


# ----------------------------------------------------------------
# Formatter
# ----------------------------------------------------------------
def format_snapshots_result(result: Any) -> None:
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if data.get("error"):
        console.print(f"  [bold red]✗[/bold red] {data['error']}")
        return

    snapshots = data.get("snapshots", [])
    public = [s for s in snapshots if s.get("public")]
    console.print(
        f"  Found [bold]{len(snapshots)}[/bold] resource(s) across "
        f"[bold]{data.get('regions_scanned', 0)}[/bold] region(s) — "
        f"[bold {'red' if public else 'green'}]{len(public)} public[/bold]"
    )

    if not snapshots:
        return

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Resource ID", style="bold cyan")
    tbl.add_column("Type", style="dim")
    tbl.add_column("Description")
    tbl.add_column("Size", style="dim")
    tbl.add_column("Enc", style="dim")
    tbl.add_column("Public", style="bold")
    tbl.add_column("Region", style="dim")

    for s in snapshots:
        pub = s.get("public", False)
        tbl.add_row(
            s.get("resource_id", ""),
            s.get("type", ""),
            (s.get("description") or "")[:60],
            str(s.get("size_gb", "")) + " GB" if s.get("size_gb") else "—",
            "✓" if s.get("encrypted") else "[red]✗[/red]",
            "[bold red]YES[/bold red]" if pub else "[dim]no[/dim]",
            s.get("region", ""),
        )

    console.print(tbl)


@technique(
    technique_id="discovery/enum_snapshots",
    tactic="discovery",
    mitre_id="T1580",
    providers=[],
    severity="high",
    safe=True,
    description="Enumerate EBS snapshots and AMIs; flag public ones. Works with or without credentials.",
    formatter=format_snapshots_result,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "region",
            "Region(s) to scan: auto-detected if omitted, 'all' for every region, "
            "or comma-separated list (e.g. us-east-1,eu-west-1).",
            required=False,
            default=None,
            example="us-east-1",
        ),
        Parameter(
            "account_id",
            "Target AWS account ID (unauthenticated mode only). "
            "Filters public snapshots/AMIs to those owned by this account.",
            required=False,
            example="123456789012",
        ),
        Parameter(
            "search",
            "Keyword to filter snapshot/AMI descriptions (unauthenticated mode). "
            "Use to narrow results when no account_id is known.",
            required=False,
            example="prod",
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    if ctx.session is not None:
        return _exec_authenticated(ctx)
    return _exec_anonymous(ctx)


def _exec_authenticated(ctx: ExecutionContext) -> dict[str, Any]:
    """Audit your own account: find snapshots/AMIs you own that are public."""
    if ctx.provider_name != "aws":
        return {
            "status": "error",
            "error": f"Authenticated snapshot enumeration not yet implemented for {ctx.provider_name}",
            "snapshots": [],
        }

    try:
        from botocore.exceptions import ClientError
    except ImportError:
        return {"error": "boto3 not installed.", "snapshots": []}

    regions = _resolve_regions(ctx, session=ctx.session)
    if isinstance(regions, dict):
        return regions

    ctx.info(f"Authenticated scan — {len(regions)} region(s) for owned snapshots and AMIs...")

    snapshots: list[dict[str, Any]] = []
    for region in regions:
        try:
            ec2 = ctx.session.client("ec2", region_name=region)
            snapshots.extend(_enum_snapshots(ec2, region))
            snapshots.extend(_enum_amis(ec2, region))
        except ClientError as e:
            logger.debug("Skipping region %s: %s", region, e)

    public_count = sum(1 for s in snapshots if s.get("public"))
    if public_count:
        ctx.info(f"[bold red]⚠ {public_count} public resource(s) found.[/bold red]")

    return {
        "snapshots": snapshots,
        "total": len(snapshots),
        "public_count": public_count,
        "regions_scanned": len(regions),
    }


def _exec_anonymous(ctx: ExecutionContext) -> dict[str, Any]:
    """External recon: find public snapshots/AMIs in a target account (no creds needed)."""
    try:
        from botocore import UNSIGNED
        from botocore.config import Config
    except ImportError:
        return {"error": "boto3 not installed.", "snapshots": []}

    account_id = ctx.get_param("account_id") or ""
    search = ctx.get_param("search") or ""

    if not account_id and not search:
        return {
            "error": (
                "Unauthenticated mode requires 'account_id' or 'search' to scope results. "
                "Example: account_id=123456789012  or  search=prod"
            ),
            "snapshots": [],
        }

    regions = _resolve_regions(ctx, session=None)
    if isinstance(regions, dict):
        return regions

    ctx.info(f"Anonymous scan — {len(regions)} region(s), no credential required...")

    anon_cfg = Config(signature_version=UNSIGNED)
    snapshots: list[dict[str, Any]] = []

    for region in regions:
        try:
            ec2 = boto3.client("ec2", region_name=region, config=anon_cfg)
            snapshots.extend(_enum_snapshots_public(ec2, region, account_id, search))
            snapshots.extend(_enum_amis_public(ec2, region, account_id, search))
        except Exception as e:
            logger.debug("Skipping region %s (anonymous): %s", region, e)

    return {
        "snapshots": snapshots,
        "total": len(snapshots),
        "public_count": len(snapshots),  # all results are public by definition
        "regions_scanned": len(regions),
        "mode": "anonymous",
    }


# ----------------------------------------------------------------
# Region resolution
# ----------------------------------------------------------------

# Regions used when no credential is available to call DescribeRegions.
_COMMON_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
]


def _resolve_regions(ctx: ExecutionContext, session=None) -> list[str] | dict:
    """Return the list of regions to scan based on the 'region' param."""
    try:
        from botocore.exceptions import ClientError
    except ImportError:
        return {"error": "boto3 not installed.", "snapshots": []}

    region_param = ctx.get_param("region")

    if region_param and region_param.lower() != "all":
        return [r.strip() for r in region_param.split(",") if r.strip()]

    if session is None:
        # No credential — fall back to common regions
        return _COMMON_REGIONS

    try:
        ec2 = session.client("ec2")
        if region_param and region_param.lower() == "all":
            resp = ec2.describe_regions(AllRegions=True)
        else:
            resp = ec2.describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opted-in", "opt-in-not-required"]}]
            )
        return [r["RegionName"] for r in resp.get("Regions", [])]
    except ClientError:
        return ["us-east-1"]


# ----------------------------------------------------------------
# EBS snapshot enumeration
# ----------------------------------------------------------------

def _enum_snapshots(ec2, region: str) -> list[dict[str, Any]]:
    results = []
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                snap_id = snap.get("SnapshotId", "")
                is_public = _snapshot_is_public(ec2, snap_id)
                results.append({
                    "resource_id": snap_id,
                    "type": "snapshot",
                    "description": snap.get("Description", ""),
                    "state": snap.get("State", ""),
                    "size_gb": snap.get("VolumeSize"),
                    "encrypted": snap.get("Encrypted", False),
                    "public": is_public,
                    "region": region,
                    "start_time": str(snap.get("StartTime", "")),
                    "volume_id": snap.get("VolumeId", ""),
                    "owner_id": snap.get("OwnerId", ""),
                })
    except Exception as e:
        logger.debug("describe_snapshots failed in %s: %s", region, e)
    return results


def _snapshot_is_public(ec2, snapshot_id: str) -> bool:
    """Return True if the snapshot has Group=all in createVolumePermission."""
    try:
        resp = ec2.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
        )
        for perm in resp.get("CreateVolumePermissions", []):
            if perm.get("Group") == "all":
                return True
    except Exception as e:
        logger.debug("describe_snapshot_attribute failed for %s: %s", snapshot_id, e)
    return False


# ----------------------------------------------------------------
# AMI enumeration
# ----------------------------------------------------------------

def _enum_amis(ec2, region: str) -> list[dict[str, Any]]:
    results = []
    try:
        resp = ec2.describe_images(Owners=["self"])
        for image in resp.get("Images", []):
            results.append({
                "resource_id": image.get("ImageId", ""),
                "type": "ami",
                "description": image.get("Description") or image.get("Name", ""),
                "state": image.get("State", ""),
                "size_gb": sum(
                    (m.get("Ebs", {}).get("VolumeSize") or 0)
                    for m in image.get("BlockDeviceMappings", [])
                ) or None,
                "encrypted": all(
                    m.get("Ebs", {}).get("Encrypted", False)
                    for m in image.get("BlockDeviceMappings", [])
                    if m.get("Ebs")
                ),
                "public": image.get("Public", False),
                "region": region,
                "start_time": image.get("CreationDate", ""),
                "owner_id": image.get("OwnerId", ""),
                "architecture": image.get("Architecture", ""),
            })
    except Exception as e:
        logger.debug("describe_images failed in %s: %s", region, e)
    return results


# ----------------------------------------------------------------
# Anonymous (unauthenticated) enumeration
# ----------------------------------------------------------------

def _enum_snapshots_public(ec2, region: str, account_id: str, search: str) -> list[dict[str, Any]]:
    """Find publicly restorable snapshots using anonymous API calls."""
    results = []
    try:
        kwargs: dict[str, Any] = {"RestorableByUserIds": ["all"]}
        if account_id:
            kwargs["OwnerIds"] = [account_id]
        if search:
            kwargs["Filters"] = [{"Name": "description", "Values": [f"*{search}*"]}]

        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(**kwargs):
            for snap in page.get("Snapshots", []):
                results.append({
                    "resource_id": snap.get("SnapshotId", ""),
                    "type": "snapshot",
                    "description": snap.get("Description", ""),
                    "state": snap.get("State", ""),
                    "size_gb": snap.get("VolumeSize"),
                    "encrypted": snap.get("Encrypted", False),
                    "public": True,
                    "region": region,
                    "start_time": str(snap.get("StartTime", "")),
                    "owner_id": snap.get("OwnerId", ""),
                })
    except Exception as e:
        logger.debug("anonymous describe_snapshots failed in %s: %s", region, e)
    return results


def _enum_amis_public(ec2, region: str, account_id: str, search: str) -> list[dict[str, Any]]:
    """Find public AMIs using anonymous API calls."""
    results = []
    try:
        kwargs: dict[str, Any] = {"ExecutableUsers": ["all"]}
        if account_id:
            kwargs["Owners"] = [account_id]
        filters = []
        if search:
            filters.append({"Name": "name", "Values": [f"*{search}*"]})
        if filters:
            kwargs["Filters"] = filters

        resp = ec2.describe_images(**kwargs)
        for image in resp.get("Images", []):
            results.append({
                "resource_id": image.get("ImageId", ""),
                "type": "ami",
                "description": image.get("Description") or image.get("Name", ""),
                "state": image.get("State", ""),
                "size_gb": sum(
                    (m.get("Ebs", {}).get("VolumeSize") or 0)
                    for m in image.get("BlockDeviceMappings", [])
                ) or None,
                "encrypted": all(
                    m.get("Ebs", {}).get("Encrypted", False)
                    for m in image.get("BlockDeviceMappings", [])
                    if m.get("Ebs")
                ),
                "public": True,
                "region": region,
                "start_time": image.get("CreationDate", ""),
                "owner_id": image.get("OwnerId", ""),
                "architecture": image.get("Architecture", ""),
            })
    except Exception as e:
        logger.debug("anonymous describe_images failed in %s: %s", region, e)
    return results
