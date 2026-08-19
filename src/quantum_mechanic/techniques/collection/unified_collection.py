# ================================================================
# TECHNIQUE: collection/unified_collection
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1005 & T1530 — Unified Data Discovery
#
# PURPOSE:   A single module to scan across all available cloud
#            storage (Buckets/Blobs) and compute artifacts
#            (Disks/Snapshots).
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   1. Enumerates cloud storage (S3/Blobs/GCS/OSS) for files.
#   2. Enumerates compute snapshots for raw block scanning.
#   3. Combines findings into a single loot table.
#
# OPTIONS:
#   mode     (optional) — 'storage', 'disk', or 'all' (default).
#   snapshot (optional) — Targeted EBS snapshot scan.
#   bucket   (optional) — Targeted bucket scan.
#
# SAFE:     Yes — read-only discovery.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique
from quantum_mechanic.techniques.collection import scan_disk_content, storage_search

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = "hits"
LOOT_SCHEMA = [
    ("source", "Source", "bold cyan"),
    ("path", "Location", "white"),
    ("type", "Matched Pattern", "yellow"),
    ("note", "Note", "dim"),
]


@technique(
    technique_id="collection/unified_collection",
    tactic="collection",
    providers=["aws", "azure", "gcp", "oci"],
    severity="high",
    safe=True,
    description="Unified discovery of secrets across both object storage and disk snapshots.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "mode",
            "Scan mode: 'storage', 'disk', or 'all'.",
            default="all",
            choices=["storage", "disk", "all"],
        ),
        Parameter("target", "Target a specific bucket (storage mode)."),
        Parameter("snapshot", "Target a specific snapshot (disk mode)."),
        Parameter("region", "Cloud region to target."),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute unified collection across storage and disks."""
    mode = ctx.get_param("mode", "all")
    all_hits = []

    # 1. Object Storage Scan
    if mode in ["all", "storage"]:
        ctx.info("Initiating Object Storage scan...")
        # We can reuse the existing technique function by wrapping the context or passing it
        storage_params = {"target": ctx.get_param("target")}
        with ctx.subtask("storage_search", params=storage_params) as sub_ctx:
            res = storage_search.execute(sub_ctx)
            for hit in res.get("hits", []):
                all_hits.append(
                    {
                        "source": "Object Storage",
                        "path": f"{hit.get('bucket')}/{hit.get('key')}",
                        "type": hit.get("type", "Pattern Match"),
                        "note": f"Provider: {ctx.provider_name}",
                    }
                )

    # 2. Disk / Snapshot Scan
    if mode in ["all", "disk"]:
        ctx.info("Initiating Disk Snapshot scan...")
        disk_params = {"snapshot": ctx.get_param("snapshot"), "region": ctx.get_param("region")}

        # If no targeted snapshot, we should ideally enumerate them first
        # For now, we rely on the targeted snapshot param or existing mounts
        if ctx.provider_name == "aws" and not disk_params["snapshot"]:
            ctx.info(
                "No specific snapshot provided. Skipping AWS Direct scan (auto-enumeration coming soon)."
            )
        else:
            with ctx.subtask("scan_disk_content", params=disk_params) as sub_ctx:
                res = scan_disk_content.execute(sub_ctx)
                for hit in res.get("hits", []):
                    all_hits.append(
                        {
                            "source": "Disk/Snapshot",
                            "path": hit.get("path"),
                            "type": hit.get("type"),
                            "note": "Ghost Scan"
                            if "Block" in hit.get("path", "")
                            else "Mount Scan",
                        }
                    )

    return {"hits": all_hits, "count": len(all_hits), "mode": mode}
