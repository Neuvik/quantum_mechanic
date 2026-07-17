import json
from unittest.mock import MagicMock, patch
import pytest
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell.commands import ShellState, cmd_check_ca_bypasses

@pytest.fixture
def workspace_dir(tmp_path):
    ws_dir = tmp_path / "workspaces"
    ws_dir.mkdir()
    return ws_dir

@pytest.fixture
def mock_console():
    with patch("quantum_mechanic.shell.commands.console.print") as mock_print:
        yield mock_print

@pytest.fixture
def state_with_ws(workspace_dir) -> ShellState:
    ws = Workspace.create("test-ws", workspace_dir=workspace_dir)
    registry = ProviderRegistry()
    s = ShellState(workspace=ws, registry=registry, workspace_dir=workspace_dir)
    yield s
    ws.close()

def test_check_ca_bypasses_no_workspace(mock_console):
    registry = ProviderRegistry()
    state = ShellState(workspace=None, registry=registry, workspace_dir=None)
    cmd_check_ca_bypasses(state, [])
    mock_console.assert_called_once()
    assert "No active workspace" in str(mock_console.call_args[0][0])

def test_check_ca_bypasses_no_data(state_with_ws, mock_console):
    cmd_check_ca_bypasses(state_with_ws, [])
    output = "".join(str(c[0][0]) for c in mock_console.call_args_list)
    assert "No Conditional Access policy data found" in output

def test_check_ca_bypasses_with_evidence(state_with_ws, mock_console):
    # Save mock users/groups/apps evidence (lowercase GUIDs)
    state_with_ws.workspace.save_evidence(
        "discovery/entra_enum_users",
        json.dumps({
            "users": [
                {"id": "user-guid-123", "userPrincipalName": "resolved-user@acme-corp.example"}
            ]
        })
    )
    state_with_ws.workspace.save_evidence(
        "discovery/entra_enum_groups",
        json.dumps({
            "groups": [
                {"id": "group-guid-456", "displayName": "Resolved Group Name"}
            ]
        })
    )

    # Insert mock evidence into database
    mock_policies = [
        {
            "display_name": "Test CA Policy",
            "state": "enabled",
            "grant_controls": "mfa",
            "excluded_users": "USER-GUID-123, user-exclude-2",
            "excluded_groups": "GROUP-GUID-456",
            "excluded_roles": "Global Administrator",
            "excluded_apps": "App A",
            "exclude_platforms": "iOS",
            "excluded_locations": "Named Loc 1",
            "client_app_types": "exchangeactivesync, other",
            "id": "policy-1"
        },
        {
            "display_name": "Disabled Policy",
            "state": "disabled",
            "grant_controls": "mfa",
            "id": "policy-2"
        }
    ]
    payload = {"policies": mock_policies}
    state_with_ws.workspace.save_evidence(
        "discovery/entra_enum_conditional_access_policies",
        json.dumps(payload)
    )

    cmd_check_ca_bypasses(state_with_ws, [])
    
    # Helper to extract text from mock console print calls (handling Rich Table objects)
    from rich.table import Table
    def get_console_text(call_args_list) -> str:
        text = []
        for call in call_args_list:
            if not call[0]:
                continue
            arg = call[0][0]
            if isinstance(arg, Table):
                if arg.title:
                    text.append(str(arg.title))
                for col in arg.columns:
                    text.append(str(col.header))
                for row_idx in range(arg.row_count):
                    row_cells = [str(arg.columns[col_idx]._cells[row_idx]) for col_idx in range(len(arg.columns))]
                    text.extend(row_cells)
            else:
                text.append(str(arg))
        return "\n".join(text)

    output = get_console_text(mock_console.call_args_list)
    
    assert "CONDITIONAL ACCESS AGGREGATED BYPASS OPPORTUNITIES" in output
    assert "resolved-user@acme-corp.example" in output
    assert "Resolved Group Name" in output
    assert "Global Administrator" in output
    assert "App A" in output
    assert "iOS" in output
    assert "Named Loc 1" in output
    assert "exchangeactivesync" in output
    assert "Disabled Policy" in output
