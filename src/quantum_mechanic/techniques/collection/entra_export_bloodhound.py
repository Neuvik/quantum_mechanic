# ================================================================
# TECHNIQUE: collection/entra_export_bloodhound
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1213 — Data from Information Repositories
#
# PURPOSE:   Export Entra ID discovery data (users, groups, apps,
#            role assignments) into BloodHound OpenGraph JSON so
#            blue teams can visualize cloud attack paths alongside
#            their on-prem AD graphs.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   Reads evidence rows from the workspace for prior Entra discovery
#   technique runs (entra_enum_users, entra_enum_groups,
#   entra_enum_apps, entra_enum_privileged_roles,
#   entra_enum_group_members). Transforms each entity into a
#   BloodHound OpenGraph node/edge and writes the result as
#   `bloodhound.json` in the workspace loot directory.
#
#   No live Graph calls. Purely transforms data already collected.
#
# DETECTION (Blue Team):
#   N/A — fully offline transformation of locally-stored evidence.
#
# OPSEC:     None — local file write only.
# SAFE:      Yes — read-only from workspace; writes to loot dir.
# ================================================================

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# Source technique IDs we know how to transform.
_SOURCE_TECHNIQUES = {
    "discovery/entra_enum_users",
    "discovery/entra_enum_groups",
    "discovery/entra_enum_apps",
    "discovery/entra_enum_privileged_roles",
    "discovery/entra_enum_group_members",
}


def _make_user_node(u: dict[str, Any]) -> dict[str, Any] | None:
    uid = u.get("id")
    if not uid:
        return None
    return {
        "id": uid,
        "kinds": ["AZUser"],
        "properties": {
            "name": u.get("userPrincipalName") or u.get("displayName") or uid,
            "display_name": u.get("displayName"),
            "user_type": u.get("userType", "Member"),
        },
    }


def _make_group_node(g: dict[str, Any]) -> dict[str, Any] | None:
    gid = g.get("id")
    if not gid:
        return None
    return {
        "id": gid,
        "kinds": ["AZGroup"],
        "properties": {
            "name": g.get("displayName") or gid,
            "group_type": g.get("group_type"),
            "is_assignable_to_role": g.get("isAssignableToRole", False),
        },
    }


def _make_app_node(a: dict[str, Any]) -> dict[str, Any] | None:
    aid = a.get("id") or a.get("appId")
    if not aid:
        return None
    return {
        "id": aid,
        "kinds": ["AZApp"],
        "properties": {
            "name": a.get("displayName") or aid,
            "app_id": a.get("appId"),
            "type": a.get("type"),
            "highest_perm_tier": a.get("highest_perm_tier", "Unknown"),
            "sign_in_audience": a.get("signInAudience"),
        },
    }


def _make_role_node(role_id: str, role_name: str, tier: str) -> dict[str, Any]:
    return {
        "id": role_id,
        "kinds": ["AZRole"],
        "properties": {
            "name": role_name,
            "tier": tier,
        },
    }


def _transform_evidence(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Walk evidence rows and build (nodes, edges) lists.

    Returns deduplicated lists keyed by node id / (start, end, kind).
    """
    nodes_by_id: dict[str, dict] = {}
    edges_by_key: dict[tuple[str, str, str], dict] = {}

    for row in rows:
        tech_id = row.get("technique_id")
        if tech_id not in _SOURCE_TECHNIQUES:
            continue
        try:
            data = json.loads(row.get("output_json", "{}"))
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue

        if tech_id == "discovery/entra_enum_users":
            for u in data.get("users", []):
                node = _make_user_node(u)
                if node:
                    nodes_by_id[node["id"]] = node

        elif tech_id == "discovery/entra_enum_groups":
            for g in data.get("groups", []):
                node = _make_group_node(g)
                if node:
                    nodes_by_id[node["id"]] = node

        elif tech_id == "discovery/entra_enum_apps":
            for a in data.get("apps", []):
                node = _make_app_node(a)
                if node:
                    nodes_by_id[node["id"]] = node

        elif tech_id == "discovery/entra_enum_privileged_roles":
            for assn in data.get("assignments", []):
                role_id = assn.get("role_id")
                role_name = assn.get("role_name", "Unknown Role")
                tier = assn.get("tier", "Unknown")
                principal_id = assn.get("principal_id")
                if not role_id or not principal_id:
                    continue
                nodes_by_id[role_id] = _make_role_node(role_id, role_name, tier)
                key = (principal_id, role_id, "AZHasRole")
                edges_by_key[key] = {
                    "start": {"value": principal_id},
                    "end": {"value": role_id},
                    "kind": "AZHasRole",
                    "properties": {"tier": tier},
                }

        elif tech_id == "discovery/entra_enum_group_members":
            for m in data.get("members", []):
                gid = m.get("group_id")
                mid = m.get("member_id")
                if not gid or not mid:
                    continue
                key = (mid, gid, "AZMemberOf")
                edges_by_key[key] = {
                    "start": {"value": mid},
                    "end": {"value": gid},
                    "kind": "AZMemberOf",
                }

    return list(nodes_by_id.values()), list(edges_by_key.values())


@technique(
    technique_id="collection/entra_export_bloodhound",
    tactic="collection",
    mitre_id="T1213",
    providers=["entra"],
    severity="info",
    safe=True,
    description="Export Entra ID discovery data as BloodHound OpenGraph JSON.",
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute the BloodHound export."""
    try:
        rows = ctx.workspace.list_evidence()
    except Exception as e:
        logger.warning("Failed to list evidence rows: %s", e)
        return {"error": str(e)}

    nodes, edges = _transform_evidence(rows)

    document = {
        "graph": {
            "metadata": {
                "source_kind": "QuantumMechanic",
                "collected_at": datetime.now(UTC).isoformat(),
            },
            "nodes": nodes,
            "edges": edges,
        }
    }

    out_dir = getattr(ctx.workspace, "workspace_dir", Path("."))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "bloodhound.json"

    try:
        out_path.write_text(json.dumps(document, indent=2))
    except Exception as e:
        logger.warning("Failed to write bloodhound.json: %s", e)
        return {"error": str(e)}

    return {
        "status": "success",
        "output_path": str(out_path),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
