"""Tests for the EAM classifier library."""
from quantum_mechanic.providers.entra import eam


def test_tier_constants_exist():
    """OUTCOME: Tier names are exported as module constants for callers to compare."""
    assert eam.TIER_CONTROL_PLANE == "ControlPlane"
    assert eam.TIER_MANAGEMENT_PLANE == "ManagementPlane"
    assert eam.TIER_WORKLOAD_PLANE == "WorkloadPlane"
    assert eam.TIER_USER_ACCESS == "UserAccess"
    assert eam.TIER_UNKNOWN == "Unknown"


def test_classify_role_name_global_admin_is_control_plane():
    """OUTCOME: Built-in role Global Administrator classifies as ControlPlane."""
    assert eam.classify_role_name("Global Administrator") == "ControlPlane"


def test_classify_role_name_helpdesk_admin_is_management_plane():
    """OUTCOME: Helpdesk Administrator classifies as ManagementPlane."""
    assert eam.classify_role_name("Helpdesk Administrator") == "ManagementPlane"


def test_classify_role_name_unknown_role_returns_unknown():
    """OUTCOME: Unknown role names return Unknown — never raise, never default to Tier 0."""
    assert eam.classify_role_name("Made Up Role That Does Not Exist") == "Unknown"


def test_classify_role_action_credentials_update_is_control_plane():
    """OUTCOME: Action that allows minting app credentials is ControlPlane (tenant takeover)."""
    action = "microsoft.directory/applications/credentials/update"
    assert eam.classify_role_action(action) == "ControlPlane"


def test_classify_role_action_unknown_action_returns_unknown():
    """OUTCOME: Unknown role-action strings return Unknown."""
    assert eam.classify_role_action("microsoft.directory/madeup/action") == "Unknown"


def test_classify_graph_permission_rolemanagement_readwrite_is_control_plane():
    """OUTCOME: RoleManagement.ReadWrite.Directory is ControlPlane."""
    assert eam.classify_graph_permission("RoleManagement.ReadWrite.Directory") == "ControlPlane"


def test_classify_graph_permission_unknown_returns_unknown():
    """OUTCOME: Unknown Graph perms return Unknown."""
    assert eam.classify_graph_permission("MadeUp.Permission.All") == "Unknown"


def test_classify_role_name_is_case_sensitive_but_handles_whitespace():
    """OUTCOME: Lookup tolerates trailing whitespace from API responses."""
    assert eam.classify_role_name("Global Administrator ") == "ControlPlane"
    assert eam.classify_role_name(" Global Administrator") == "ControlPlane"


def test_classify_role_action_none_input_returns_unknown():
    """OUTCOME: None input returns Unknown, not crash."""
    assert eam.classify_role_action(None) == "Unknown"
    assert eam.classify_role_name(None) == "Unknown"
    assert eam.classify_graph_permission(None) == "Unknown"
