from __future__ import annotations


_BUNDLES: dict[str, list[str]] = {
    "basic-graph": [
        "User.Read",
    ],
    "ca-read": [
        "Policy.Read.ConditionalAccess",
    ],
    "pim-read": [
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
    ],
    "entra-admin-read": [
        "Directory.Read.All",
        "Policy.Read.ConditionalAccess",
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
    ],
}


def resolve_scope_bundle(name: str) -> list[str] | None:
    """Return the explicit delegated scopes for a human bundle name."""
    return _BUNDLES.get(name)


def build_scope_string(resource: str, scopes: list[str] | None) -> str:
    """Build the OAuth v2 scope string for Entra token acquisition.

    No explicit scopes keeps the legacy `resource/.default` bootstrap path.
    Explicit scopes are fully-qualified on the resource and always include
    openid + offline_access.
    """
    resource_root = resource.rstrip("/")
    if not scopes:
        return f"{resource_root}/.default openid offline_access"

    qualified = [f"{resource_root}/{scope}" for scope in scopes]
    return " ".join([*qualified, "openid", "offline_access"])
