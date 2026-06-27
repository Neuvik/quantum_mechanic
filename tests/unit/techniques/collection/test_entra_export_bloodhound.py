"""Unit tests for collection/entra_export_bloodhound."""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from quantum_mechanic.techniques.collection.entra_export_bloodhound import execute


def _make_ctx(tmpdir: Path, evidence_rows: list[dict]) -> MagicMock:
    """Build a context with a workspace that returns the given evidence rows."""
    ctx = MagicMock()
    ctx.provider_name = "entra"
    ctx.workspace = MagicMock()
    ctx.workspace.list_evidence.return_value = evidence_rows
    ctx.workspace.workspace_dir = tmpdir
    return ctx


def test_empty_workspace_produces_empty_graph():
    """OUTCOME: zero evidence rows → valid empty graph JSON written to disk."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, [])

        result = execute(ctx)

        assert result["status"] == "success"
        out_path = Path(result["output_path"])
        assert out_path.exists()
        body = json.loads(out_path.read_text())
        assert body["graph"]["nodes"] == []
        assert body["graph"]["edges"] == []
        assert body["graph"]["metadata"]["source_kind"] == "QuantumMechanic"


def test_user_and_role_assignment_produce_node_plus_edge():
    """OUTCOME: One user + one role assignment → 2 nodes + 1 AZHasRole edge."""
    evidence = [
        {
            "technique_id": "discovery/entra_enum_users",
            "output_json": json.dumps({
                "users": [
                    {
                        "id": "user-id-1",
                        "userPrincipalName": "alice@contoso.com",
                        "displayName": "Alice",
                        "userType": "Member",
                    }
                ]
            }),
        },
        {
            "technique_id": "discovery/entra_enum_privileged_roles",
            "output_json": json.dumps({
                "assignments": [
                    {
                        "role_id": "role-id-1",
                        "role_name": "Global Administrator",
                        "tier": "ControlPlane",
                        "principal_id": "user-id-1",
                        "principal_name": "alice@contoso.com",
                        "principal_type": "user",
                    }
                ]
            }),
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, evidence)

        result = execute(ctx)

        body = json.loads(Path(result["output_path"]).read_text())
        nodes = body["graph"]["nodes"]
        edges = body["graph"]["edges"]

        # 2 nodes: user + role
        assert len(nodes) == 2
        kinds = {n["kinds"][0] for n in nodes}
        assert "AZUser" in kinds
        assert "AZRole" in kinds

        # 1 edge: user → role
        assert len(edges) == 1
        assert edges[0]["kind"] == "AZHasRole"
        assert edges[0]["start"]["value"] == "user-id-1"
        assert edges[0]["end"]["value"] == "role-id-1"

        # Tier on the edge
        assert edges[0]["properties"]["tier"] == "ControlPlane"


def test_role_node_carries_tier_property():
    """OUTCOME: Role nodes get a `tier` property set from the assignment's tier."""
    evidence = [
        {
            "technique_id": "discovery/entra_enum_privileged_roles",
            "output_json": json.dumps({
                "assignments": [
                    {
                        "role_id": "role-id-1",
                        "role_name": "Global Administrator",
                        "tier": "ControlPlane",
                        "principal_id": "p1",
                        "principal_name": "p1@x.com",
                        "principal_type": "user",
                    }
                ]
            }),
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, evidence)
        result = execute(ctx)
        body = json.loads(Path(result["output_path"]).read_text())
        role_nodes = [n for n in body["graph"]["nodes"] if "AZRole" in n["kinds"]]
        assert len(role_nodes) == 1
        assert role_nodes[0]["properties"]["tier"] == "ControlPlane"
        assert role_nodes[0]["properties"]["name"] == "Global Administrator"


def test_group_members_produce_memberof_edges():
    """OUTCOME: entra_enum_group_members evidence produces AZMemberOf edges."""
    evidence = [
        {
            "technique_id": "discovery/entra_enum_group_members",
            "output_json": json.dumps({
                "group_id": "group-id-1",
                "group_name": "Admins",
                "members": [
                    {
                        "group_id": "group-id-1",
                        "group_name": "Admins",
                        "member_id": "user-id-1",
                        "member_name": "alice@contoso.com",
                        "member_type": "user",
                    }
                ],
            }),
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, evidence)
        result = execute(ctx)
        body = json.loads(Path(result["output_path"]).read_text())
        edges = body["graph"]["edges"]
        memberof = [e for e in edges if e["kind"] == "AZMemberOf"]
        assert len(memberof) == 1
        assert memberof[0]["start"]["value"] == "user-id-1"
        assert memberof[0]["end"]["value"] == "group-id-1"


def test_apps_produce_azapp_nodes():
    """OUTCOME: entra_enum_apps evidence produces AZApp nodes with highest_perm_tier property."""
    evidence = [
        {
            "technique_id": "discovery/entra_enum_apps",
            "output_json": json.dumps({
                "apps": [
                    {
                        "id": "app-id-1",
                        "appId": "appid-1",
                        "displayName": "Privileged App",
                        "type": "App Registration",
                        "signInAudience": "AzureADMyOrg",
                        "highest_perm_tier": "ControlPlane",
                    },
                ],
            }),
        },
    ]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, evidence)
        result = execute(ctx)
        body = json.loads(Path(result["output_path"]).read_text())
        app_nodes = [n for n in body["graph"]["nodes"] if "AZApp" in n["kinds"]]
        assert len(app_nodes) == 1
        assert app_nodes[0]["properties"]["highest_perm_tier"] == "ControlPlane"
        assert app_nodes[0]["properties"]["name"] == "Privileged App"


def test_output_path_returned_in_result():
    """OUTCOME: result dict contains output_path pointing to written bloodhound.json."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, [])
        result = execute(ctx)
        assert "output_path" in result
        assert result["output_path"].endswith("bloodhound.json")
        assert Path(result["output_path"]).is_file()


def test_output_json_is_valid():
    """OUTCOME: Written file is valid JSON parseable as a BloodHound OpenGraph document."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _make_ctx(tmp, [])
        result = execute(ctx)
        text = Path(result["output_path"]).read_text()
        body = json.loads(text)  # must not raise
        assert "graph" in body
        assert "metadata" in body["graph"]
        assert "nodes" in body["graph"]
        assert "edges" in body["graph"]
