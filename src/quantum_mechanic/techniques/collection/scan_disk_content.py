# ================================================================
# TECHNIQUE: collection/scan_disk_content
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1005 — Data from Local System
#
# PURPOSE:   Search for sensitive files (secrets, keys, configs)
#            within a mounted disk volume or AWS EBS snapshot.
#
# PROVIDERS: AWS, Azure, GCP, OCI (Unified Local Scan)
#
# HOW IT WORKS:
#   Local: Crawls the directory provided in the 'target' option.
#          Skips noisy system directories (/dev, /proc, node_modules).
#
#   AWS Direct: Uses ebs:ListSnapshotBlocks and ebs:GetSnapshotBlock
#               to sample raw disk blocks for secret markers.
#               (Zero-Mount execution).
#
# OPTIONS:
#   target   (optional) — The local path or mount point to scan.
#   snapshot (optional) — AWS EBS Snapshot ID to scan directly.
#   regex    (optional) — Custom regex for file matching.
#
# DETECTION (Blue Team):
#   AWS: Monitor for high-volume GetSnapshotBlock API calls.
#   Local: Monitor for rapid recursive file listing in sensitive dirs.
#
# SAFE:     Yes — read-only discovery.
# ================================================================

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

# Re-use patterns from disk_scanner.py logic
DEFAULT_PATTERNS = {
    "AWS Credentials":  r"^credentials$",
    "SSH Private Key":  r"^id_(rsa|dsa|ed25519|ecdsa)$",
    "Environment File": r"^\.env(\..*)?$",
    "Kubeconfig":       r"^config$",
    "Terraform State":  r".*\.tfstate$",
    "Shadow File":      r"^shadow$",
}

# ----------------------------------------------------------------
# Loot schema
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'hits'
LOOT_SCHEMA = [
    ('label',   'Type',     'bold cyan'),
    ('path',    'Location', 'white'),
    ('size',    'Size',     'dim'),
    ('type',    'Matched Pattern', 'yellow'),
]

@technique(
    technique_id="collection/scan_disk_content",
    tactic='collection',
    mitre_id="T1005",
    providers=["aws"],
    severity="high",
    safe=True,
    description="Scan a mounted disk volume or AWS EBS snapshot for credentials and secrets.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "The mount point or local directory to scan.", required=False, example="/mnt/stolen-disk"),
        Parameter("snapshot", "AWS EBS Snapshot ID to scan directly (AWS only).", required=False, example="snap-0123456789"),
        Parameter("region", "AWS Region for the snapshot (AWS only).", required=False, example="us-east-1"),
        Parameter("regex", "Custom regex for file matching (optional)."),
    ]
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute disk scan (Local Path or AWS Direct)."""
    snapshot_id = ctx.get_param("snapshot")
    region = ctx.get_param("region")
    mount_point = ctx.get_param("target")

    if ctx.provider_name == "aws" and snapshot_id:
        return _scan_aws_direct(ctx, snapshot_id, region)

    if not mount_point:
        return {"error": "Target path ('target') is required for local disk scanning."}

    return _scan_local(ctx, mount_point)


def _scan_aws_direct(ctx: ExecutionContext, snapshot_id: str, region: str | None) -> dict[str, Any]:
    """Ghost-scan an AWS EBS snapshot using Direct APIs (Zero-Mount)."""
    # Use provided region or fallback to session default
    initial_region = region or ctx.session.region_name or "us-east-1"

    # Binary-safe markers for secrets
    patterns = [
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"AWS_SECRET_ACCESS_KEY",
        b"DB_PASSWORD",
        b"\"api_key\":",
        b"REPRO_SECRET_MARKER",
    ]
    hits = []

    # 1. Attempt to find the snapshot and its region
    ec2 = ctx.session.client("ec2", region_name=initial_region)
    try:
        ctx.info(f"AWS Direct: Searching for snapshot {snapshot_id} starting in {initial_region}...")
        snap_info = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
        aws_region = initial_region
    except Exception:
        # Snapshot not found in initial region, try auto-discovery across common regions
        ctx.info(f"AWS Direct: Snapshot not found in {initial_region}, searching other regions...")
        found = False
        for r in ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1"]:
            if r == initial_region: continue
            try:
                temp_ec2 = ctx.session.client("ec2", region_name=r)
                snap_info = temp_ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
                aws_region = r
                ec2 = temp_ec2
                ctx.info(f"AWS Direct: Snapshot discovered in {r}")
                found = True
                break
            except Exception as e:
                logger.debug("Failed discovering snapshot in region %s: %s", r, e)
                continue

        if not found:
            return {"error": f"Snapshot {snapshot_id} not found in any common region.", "hits": []}

    ebs = ctx.session.client("ebs", region_name=aws_region)

    try:
        # 2. Wait for snapshot completion
        state = snap_info.get("State")
        if state != "completed":
            ctx.info(f"AWS Direct: Waiting for snapshot {snapshot_id} to reach 'completed' (Current: {state})...")
            waiter = ec2.get_waiter("snapshot_completed")
            waiter.wait(SnapshotIds=[snapshot_id], WaiterConfig={"MaxAttempts": 20, "Delay": 5})

        # 3. List blocks (with retries for propagation lag)
        blocks = []
        max_retries = 10
        for attempt in range(max_retries):
            try:
                # MaxResults 1000 is the API max
                resp = ebs.list_snapshot_blocks(SnapshotId=snapshot_id, MaxResults=1000)
                blocks = resp.get("Blocks", [])
                if blocks: break

                # If no blocks, but snapshot is complete, it might be an empty/zero-filled volume
                # or just propagation lag
                ctx.info(f"AWS Direct: No blocks returned yet (Attempt {attempt+1}/{max_retries})...")
                time.sleep(5)
            except Exception as api_e:
                if "ResourceNotFoundException" in str(api_e) and attempt < max_retries - 1:
                    ctx.info("AWS Direct: API says snapshot not found (lag). Retrying in 5s...")
                    time.sleep(5)
                    continue
                ctx.error(f"AWS Direct: list_snapshot_blocks failed: {api_e}")
                return {"error": str(api_e), "hits": []}

        if not blocks:
            return {"hits": [], "count": 0, "status": "empty"}

        ctx.info(f"AWS Direct: Sampling {len(blocks)} blocks for secret markers...")

        for block in blocks:
            idx = block["BlockIndex"]
            token = block["BlockToken"]

            try:
                # 4. Get the raw block data
                block_data = ebs.get_snapshot_block(
                    SnapshotId=snapshot_id,
                    BlockIndex=idx,
                    BlockToken=token
                )["BlockData"].read()

                ctx.info(f"Block {idx} read ({len(block_data)} bytes). Start (hex): {block_data[:32].hex()}")

                # 5. Heuristic pattern matching
                for p in patterns:
                    if p in block_data:
                        hits.append({
                            "label": "Direct Block Match",
                            "path": f"Snapshot: {snapshot_id} / Block: {idx}",
                            "size": len(block_data),
                            "type": p.decode()
                        })
                        ctx.success(f"Discovered secret marker '{p.decode()}' in block {idx}")
                        break

            except Exception as block_e:
                ctx.error(f"AWS Direct: Failed to read block {idx}: {block_e}")
                continue

        return {
            "hits": hits,
            "count": len(hits),
            "note": "Scanned via EBS Direct APIs (Zero-Mount)"
        }
    except Exception as e:
        return {"error": str(e), "hits": []}


def _scan_local(ctx: ExecutionContext, mount_point: str) -> dict[str, Any]:
    """Crawl a local mount point for files."""
    mount_path = Path(mount_point)
    if not mount_path.exists():
        return {"error": f"Path not found: {mount_point}", "hits": []}

    custom_regex = ctx.get_param("regex")
    ctx.info(f"Starting scan of target path: {mount_point}...")

    # Pre-compile regexes
    if custom_regex:
        compiled = {"Custom Match": re.compile(custom_regex, re.IGNORECASE)}
    else:
        compiled = {label: re.compile(pat, re.IGNORECASE) for label, pat in DEFAULT_PATTERNS.items()}

    skip_dirs = {"dev", "proc", "sys", "run", "tmp", "node_modules", "usr/share"}
    hits = []

    for root, _dirs, files in os.walk(mount_path):
        # Filter noisy dirs
        rel_path = os.path.relpath(root, mount_path)
        if any(skip in rel_path for skip in skip_dirs):
            continue

        for filename in files:
            full_path = Path(root) / filename

            try:
                if not full_path.is_file(): continue
                if full_path.stat().st_size > 10 * 1024 * 1024: continue # 10MB limit
            except Exception as e:
                logger.debug("Failed to stat file %s: %s", full_path, e)
                continue

            for label, regex in compiled.items():
                if regex.match(filename):
                    # Quick logic validation
                    if label == "AWS Credentials" and ".aws" not in str(full_path): continue

                    hits.append({
                        "label": label,
                        "path": str(full_path),
                        "size": full_path.stat().st_size,
                        "type": "File Match"
                    })
                    break

    ctx.success(f"Scan complete. Found {len(hits)} sensitive items.")
    return {
        "hits": hits,
        "count": len(hits)
    }
