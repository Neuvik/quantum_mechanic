from __future__ import annotations

from quantum_mechanic.providers.entra.scope_bundles import (
    build_scope_string,
    resolve_scope_bundle,
)


def test_resolve_scope_bundle_returns_named_bundle_scopes():
    """OUTCOME: human bundle name resolves to the expected delegated scopes."""
    assert resolve_scope_bundle("pim-read") == [
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
    ]


def test_resolve_scope_bundle_returns_none_for_unknown_bundle():
    """OUTCOME: unknown bundle names do not silently map to anything."""
    assert resolve_scope_bundle("does-not-exist") is None


def test_build_scope_string_defaults_to_default_bootstrap():
    """OUTCOME: no explicit scopes keeps the legacy /.default behavior."""
    assert build_scope_string("https://graph.microsoft.com", None) == (
        "https://graph.microsoft.com/.default openid offline_access"
    )


def test_build_scope_string_expands_explicit_scopes():
    """OUTCOME: explicit delegated scopes are fully qualified on the resource."""
    assert build_scope_string(
        "https://graph.microsoft.com",
        ["User.Read", "RoleManagement.Read.Directory"],
    ) == (
        "https://graph.microsoft.com/User.Read "
        "https://graph.microsoft.com/RoleManagement.Read.Directory "
        "openid offline_access"
    )
