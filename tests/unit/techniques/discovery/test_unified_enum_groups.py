import pytest
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.unified_enum_groups import execute, _enum_aws, _enum_gcp, _enum_oci

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.info = MagicMock()
    ctx.debug = MagicMock()
    ctx.success = MagicMock()
    ctx.error = MagicMock()
    ctx.session = MagicMock()
    return ctx

def test_enum_aws_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    iam = MagicMock()
    mock_ctx.session.client.return_value = iam
    
    # Mock pagination
    paginator = MagicMock()
    iam.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            'Groups': [
                {'GroupName': 'Admins', 'GroupId': 'G1', 'Path': '/'},
                {'GroupName': 'Developers', 'GroupId': 'G2', 'Path': '/'}
            ]
        }
    ]
    
    # Mock get_group for members
    iam.get_group.side_effect = [
        {'Users': [{'UserName': 'alice'}]},
        {'Users': [{'UserName': 'bob'}, {'UserName': 'charlie'}]}
    ]
    
    result = _enum_aws(mock_ctx)
    
    assert result["status"] == "success"
    assert len(result["groups"]) == 2
    assert result["groups"][0]["name"] == "Admins"
    assert result["groups"][0]["members"] == 1
    assert result["groups"][1]["name"] == "Developers"
    assert result["groups"][1]["members"] == 2

def test_enum_gcp_success(mock_ctx):
    mock_ctx.provider_name = "gcp"
    mock_ctx.whoami.return_value = MagicMock(account_id="test-project")
    
    with patch("google.cloud.resourcemanager_v3.ProjectsClient") as mock_client_cls:
        client = mock_client_cls.return_value
        policy = MagicMock()
        binding1 = MagicMock()
        binding1.role = "roles/owner"
        binding1.members = ["group:admins@example.com", "user:boss@example.com"]
        
        binding2 = MagicMock()
        binding2.role = "roles/viewer"
        binding2.members = ["group:devs@example.com", "group:admins@example.com"]
        
        policy.bindings = [binding1, binding2]
        client.get_iam_policy.return_value = policy
        
        result = _enum_gcp(mock_ctx)
        
        assert result["status"] == "success"
        # admins@example.com and devs@example.com
        assert len(result["groups"]) == 2
        names = [g["name"] for g in result["groups"]]
        assert "admins@example.com" in names
        assert "devs@example.com" in names

def test_enum_oci_success(mock_ctx):
    mock_ctx.provider_name = "oci"
    mock_ctx.session = {"config": {"tenancy": "ocid1.tenancy.oc1..test"}}
    
    with patch("oci.identity.IdentityClient") as mock_identity_cls:
        with patch("oci.pagination.list_call_get_all_results") as mock_pagination:
            identity = mock_identity_cls.return_value
            
            # Mock groups
            groups_resp = MagicMock()
            group1 = MagicMock()
            group1.name = "OCI-Admins"
            group1.id = "group.id.1"
            group1.description = "Admin group"
            groups_resp.data = [group1]
            
            # Mock memberships
            members_resp = MagicMock()
            members_resp.data = [MagicMock(), MagicMock()] # 2 members
            
            mock_pagination.side_effect = [groups_resp, members_resp]
            
            result = _enum_oci(mock_ctx)
            
            assert result["status"] == "success"
            assert len(result["groups"]) == 1
            assert result["groups"][0]["name"] == "OCI-Admins"
            assert result["groups"][0]["members"] == 2

def test_entra_path_delegates_to_entra_enum_groups(mock_ctx):
    """OUTCOME: entra path returns entra_enum_groups result with name/members shim applied.

    ANTI-GAMIFICATION: patching entra_enum_groups.execute verifies true delegation.
    """
    mock_ctx.provider_name = "entra"
    fake_result = {
        "provider": "entra",
        "total": 1,
        "by_type": {"security": 1},
        "groups": [
            {
                "id": "gid1",
                "displayName": "Admins",
                "description": "Admin group",
                "group_type": "security",
                "isAssignableToRole": False,
            }
        ],
    }
    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_groups.entra_enum_groups.execute",
        return_value=fake_result,
    ) as mock_delegate:
        result = execute(mock_ctx)

    mock_delegate.assert_called_once_with(mock_ctx)
    # Schema shim: name and members must be present for the unified formatter
    assert result["groups"][0]["name"] == "Admins"
    assert result["groups"][0]["members"] == 0

def test_execute_dispatch(mock_ctx):
    mock_ctx.provider_name = "aws"
    with patch("quantum_mechanic.techniques.discovery.unified_enum_groups._enum_aws") as mock_aws:
        mock_aws.return_value = {"status": "success", "groups": []}
        execute(mock_ctx)
        mock_aws.assert_called_once_with(mock_ctx)
