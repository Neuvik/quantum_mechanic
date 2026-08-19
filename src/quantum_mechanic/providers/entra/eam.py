"""Enterprise Access Model (EAM) classifier.

Loads JSON templates at import time and exposes pure-function classifiers.
Templates are sourced from EntraOps (MIT-licensed) and live alongside this
module in the `eam_data/` subdirectory.

Phase A wires `classify_role_name` and `classify_graph_permission` into
existing techniques. Phase B status (2026-06-27):

1. ✅ `entra_enum_apps` populates each application's `_resolved_perms`
   field via `providers/entra/graph_perms.GraphPermResolver`. The classifier
   sees real Graph permission names instead of UUIDs.

2. ⏳ `classify_role_action` remains unused — reserved for Phase C's
   custom directory-role enumeration via
   /roleManagement/directory/roleDefinitions with `$expand=rolePermissions`.
"""

from __future__ import annotations

import json
from pathlib import Path

# Tier name constants — use these everywhere to avoid string drift.
TIER_CONTROL_PLANE = "ControlPlane"
TIER_MANAGEMENT_PLANE = "ManagementPlane"
TIER_WORKLOAD_PLANE = "WorkloadPlane"
TIER_USER_ACCESS = "UserAccess"
TIER_UNKNOWN = "Unknown"

_TEMPLATE_DIR = Path(__file__).parent / "eam_data"


def _load(name: str) -> dict[str, str]:
    with (_TEMPLATE_DIR / name).open(encoding="utf-8") as f:
        return json.load(f)


# Loaded once at module import. Lookups are O(1) dict gets.
_ROLE_NAMES = _load("directory_roles.json")
_ROLE_ACTIONS = _load("role_actions.json")
_GRAPH_PERMS = _load("graph_permissions.json")


def classify_role_name(name: str | None) -> str:
    """Return the EAM tier for a built-in directory role display name."""
    if not name:
        return TIER_UNKNOWN
    return _ROLE_NAMES.get(name.strip(), TIER_UNKNOWN)


def classify_role_action(action: str | None) -> str:
    """Return the EAM tier for a single role-action string.

    Example: `microsoft.directory/applications/credentials/update` → `ControlPlane`.
    """
    if not action:
        return TIER_UNKNOWN
    return _ROLE_ACTIONS.get(action.strip(), TIER_UNKNOWN)


def classify_graph_permission(perm: str | None) -> str:
    """Return the EAM tier for a Microsoft Graph permission name.

    Example: `RoleManagement.ReadWrite.Directory` → `ControlPlane`.
    """
    if not perm:
        return TIER_UNKNOWN
    return _GRAPH_PERMS.get(perm.strip(), TIER_UNKNOWN)
