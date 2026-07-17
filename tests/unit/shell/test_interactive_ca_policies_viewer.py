import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.shell.commands import ShellState, _interactive_ca_policies_viewer

@pytest.fixture
def workspace_dir(tmp_path):
    ws_dir = tmp_path / "workspaces"
    ws_dir.mkdir()
    return ws_dir

@pytest.fixture
def mock_console():
    with patch("quantum_mechanic.shell.commands.console.print") as mock_print:
        yield mock_print

def test_interactive_ca_policies_viewer_resolution(workspace_dir, mock_console):
    # 1. Create a workspace and save mock users/groups/apps evidence
    ws = Workspace.create("test-ws", workspace_dir=workspace_dir)
    db_path = Path(ws.db_path)

    # Save user evidence
    ws.save_evidence(
        "discovery/entra_enum_users",
        json.dumps({
            "users": [
                {"id": "user-guid-123", "userPrincipalName": "resolved-user@acme-corp.example"}
            ]
        })
    )
    # Save group evidence
    ws.save_evidence(
        "discovery/entra_enum_groups",
        json.dumps({
            "groups": [
                {"id": "group-guid-456", "displayName": "Resolved Group Name"}
            ]
        })
    )
    # Save app evidence
    ws.save_evidence(
        "discovery/entra_enum_apps",
        json.dumps({
            "apps": [
                {"id": "app-guid-789", "displayName": "Resolved Application Name"}
            ]
        })
    )

    # 2. Write a mock conditional access loot CSV with raw GUIDs
    loot_dir = db_path.parent / db_path.stem / "loot" / "discovery" / "entra_enum_conditional_access_policies"
    loot_dir.mkdir(parents=True, exist_ok=True)
    csv_path = loot_dir / "loot.csv"

    headers = [
        "display_name", "state", "grant_controls", 
        "included_users", "included_groups", "included_roles", 
        "included_apps", "included_platforms", "included_locations", "client_app_types",
        "excluded_users", "excluded_groups", "excluded_roles", 
        "excluded_apps", "exclude_platforms", "excluded_locations", "id"
    ]
    row = {
        "display_name": "Test CA Policy",
        "state": "enabled",
        "grant_controls": "block, persistentBrowser(never), signInFrequency(12 hours)",
        "included_users": "USER-GUID-123",
        "included_groups": "GROUP-GUID-456",
        "included_roles": "None",
        "included_apps": "APP-GUID-789",
        "included_platforms": "All",
        "included_locations": "NamedLoc-999",  # Named Location ID that will be resolved to display name
        "client_app_types": "All",
        "excluded_users": "USER-GUID-123",
        "excluded_groups": "GROUP-GUID-456",
        "excluded_roles": "None",
        "excluded_apps": "APP-GUID-789",
        "exclude_platforms": "None",
        "excluded_locations": "NamedLoc-999",
        "id": "policy-123"
    }

    # Add a mock resolved named location manually into load_loot_mappings logic by patching or using the CSV/db fallback
    # Since Named Locations are resolved dynamically from Graph during run-time, we can mock/insert it in database
    # as part of mock mappings. Wait, load_loot_mappings doesn't fetch locations from Graph (that's done during entra_enum_conditional_access_policies run).
    # But wait, during run, if it was resolved, it would have been saved with the resolved name. Let's verify.
    # Yes, during run, it resolves locations via graph and writes the resolved string to CSV. 
    # If the user has a raw GUID or custom name in CSV, we want to resolve it.

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers)
        writer.writeheader()
        writer.writerow(row)

    # 3. Call interactive viewer with mocked input sequence:
    # First: "list" (to test re-rendering summary table)
    # Second: "1" (to select the policy detail)
    # Third: "" (to exit loop)
    inputs = ["list", "1", ""]
    with patch("builtins.input", side_effect=inputs):
        _interactive_ca_policies_viewer(loot_dir, db_path)

    # Get printed output from mock console
    from rich.panel import Panel
    from rich.table import Table
    
    panels = []
    tables = []
    for call in mock_console.call_args_list:
        arg = call[0][0]
        if isinstance(arg, Panel):
            panels.append(arg)
        elif isinstance(arg, Table):
            tables.append(arg)

    # Check that summary table was rendered twice (initially + after "list")
    assert len(tables) >= 2

    # Check panel content for resolved names
    assert len(panels) == 1
    panel = panels[0]
    
    # Extract strings from the Group inside the Panel
    group = panel.renderable
    lines = [str(x) for x in group.renderables]
    joined_lines = "\n".join(lines)

    # Verify that GUIDs were resolved dynamically at display time!
    assert "resolved-user@acme-corp.example" in joined_lines
    assert "Resolved Group Name" in joined_lines
    assert "Resolved Application Name" in joined_lines

    # Verify control explanations are present in guidance!
    assert "persistentBrowser(never): Persistent browser sessions are disabled" in joined_lines
    assert "signInFrequency(12 hours): Limits the lifetime of the authentication session" in joined_lines

    # Close workspace
    ws.close()
