# ================================================================
# TESTS: tests/unit/techniques/discovery/test_enum_permissions.py
# ----------------------------------------------------------------
# PURPOSE:  Unit tests for discovery/enum_permissions.
#           All external SDK calls are mocked.
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.enum_permissions import execute

@pytest.fixture
def mock_ctx():
    """Build a minimal ExecutionContext stub."""
    ctx = MagicMock(spec=ExecutionContext)
    
    # Setup default whoami return
    mock_whoami = MagicMock()
    mock_whoami.principal_type = "user"
    mock_whoami.principal_id = "arn:aws:iam::123:user/morpheus"
    mock_whoami.friendly_name = "morpheus"
    mock_whoami.extra = {}
    
    ctx.whoami.return_value = mock_whoami
    return ctx


# ================================================================
# General Tests
# ================================================================

def test_unknown_provider_returns_error(mock_ctx):
    mock_ctx.provider_name = "unknowncloud"
    result = execute(mock_ctx)
    assert "error" in result
    assert "not yet implemented" in result["error"]


def test_unknown_principal_returns_error(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.whoami().principal_type = "unknown"
    result = execute(mock_ctx)
    assert "error" in result
    assert "determine principal" in result["error"]


# ================================================================
# AWS Tests
# ================================================================

class TestEnumPermissionsAWS:
    def _setup_aws_ctx(self, mock_ctx, simulator_results):
        mock_iam = MagicMock()
        mock_paginator = MagicMock()
        
        # Format simulator response
        page = {"EvaluationResults": simulator_results}
        mock_paginator.paginate.return_value = [page]
        
        mock_iam.get_paginator.return_value = mock_paginator
        
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda svc: mock_iam if svc == "iam" else MagicMock()
        
        mock_ctx.session = mock_session
        mock_ctx.provider_name = "aws"
        return mock_iam

    def test_aws_simulator_success(self, mock_ctx):
        sim_results = [
            {"EvalActionName": "ec2:RunInstances", "EvalDecision": "allowed"},
            {"EvalActionName": "iam:PassRole", "EvalDecision": "explicitDeny"}
        ]
        self._setup_aws_ctx(mock_ctx, sim_results)
        
        result = execute(mock_ctx)
        
        assert result["status"] == "success"
        assert result["method"] == "iam:SimulatePrincipalPolicy"
        assert "ec2:RunInstances" in result["allowed_actions"]
        assert "iam:PassRole" in result["denied_actions"]

    def test_aws_simulator_denied_uses_fallback(self, mock_ctx):
        # Setup context where IAM Simulator raises AccessDenied
        mock_iam = MagicMock()
        mock_iam.get_paginator.side_effect = Exception("Access Denied to SimulatePrincipalPolicy")
        
        mock_ec2 = MagicMock()
        
        # Setup EC2 client to throw DryRun exceptions
        class ClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}
                
        def describe_side_effect(**kwargs):
            raise ClientError("DryRunOperation")
            
        def run_side_effect(**kwargs):
            raise ClientError("UnauthorizedOperation")
            
        mock_ec2.describe_instances.side_effect = describe_side_effect
        mock_ec2.run_instances.side_effect = run_side_effect
        
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda svc: mock_iam if svc == "iam" else mock_ec2
        
        mock_ctx.session = mock_session
        mock_ctx.provider_name = "aws"
        
        result = execute(mock_ctx)
        
        assert result["status"] == "success"
        assert result["method"] == "active_dryrun_fallback"
        assert "ec2:DescribeInstances" in result["allowed_actions"]
        assert "ec2:RunInstances" in result["denied_actions"]
        assert "partial DryRun" in result.get("note", "")

# ================================================================
# Azure Tests
# ================================================================

class TestEnumPermissionsAzure:
    def test_azure_returns_effective_permissions(self, mock_ctx):
        mock_ctx.provider_name = "azure"
        mock_ctx.session = MagicMock()
        mock_ctx.whoami().extra = {"subscriptions": [{"id": "sub-123"}]}
        
        import sys
        mock_auth_mgmt = MagicMock()
        mock_client = MagicMock()
        mock_auth_mgmt.AuthorizationManagementClient.return_value = mock_client
        
        mock_perm = MagicMock()
        mock_perm.actions = ["Microsoft.Compute/virtualMachines/runCommand/action"]
        mock_perm.not_actions = ["Microsoft.Authorization/roleAssignments/write"]
        mock_perm.data_actions = []
        mock_perm.not_data_actions = []
        
        mock_client.permissions.list_for_subscription.return_value = [mock_perm]
        
        azure_mocks = {
            "azure.mgmt.authorization": mock_auth_mgmt
        }
        
        with patch.dict(sys.modules, azure_mocks):
            import importlib
            import quantum_mechanic.techniques.discovery.enum_permissions as mod
            importlib.reload(mod)
            result = mod.execute(mock_ctx)
            
        assert result["status"] == "success"
        assert "Microsoft.Compute/virtualMachines/runCommand/action" in result["allowed_actions"]
        assert "Microsoft.Authorization/roleAssignments/write" in result["denied_actions"]


# ================================================================
# GCP Tests
# ================================================================

class TestEnumPermissionsGCP:
    def test_gcp_test_permissions(self, mock_ctx):
        mock_ctx.provider_name = "gcp"
        mock_ctx.session = MagicMock()

        import sys
        mock_rm = MagicMock()
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client
        
        mock_proj = MagicMock()
        mock_proj.project_id = "my-project-123"
        mock_client.search_projects.return_value = [mock_proj]
        
        mock_resp = MagicMock()
        mock_resp.permissions = ["compute.instances.create", "iam.serviceAccounts.actAs"]
        mock_client.test_iam_permissions.return_value = mock_resp
        
        mock_google_cloud = MagicMock()
        mock_google_cloud.resourcemanager_v3 = mock_rm
        
        gcp_mocks = {
            "google.cloud": mock_google_cloud,
            "google.cloud.resourcemanager_v3": mock_rm
        }
        
        with patch.dict(sys.modules, gcp_mocks):
            import importlib
            import quantum_mechanic.techniques.discovery.enum_permissions as mod
            importlib.reload(mod)
            result = mod.execute(mock_ctx)
            
        assert result["status"] == "success"
        assert "compute.instances.create" in result["allowed_actions"]
        # Explicitly testing an action that wasn't returned as allowed
        assert "storage.buckets.list" in result["denied_actions"]

# ================================================================
# OCI Tests
# ================================================================

class TestEnumPermissionsOCI:
    def test_oci_active_probing(self, mock_ctx):
        mock_ctx.provider_name = "oci"
        mock_ctx.session = {"config": {"tenancy": "ocid1.tenancy.oc1..123"}}
        
        import sys
        
        # Mock OCI exceptions and SDK
        class ServiceError(Exception):
            def __init__(self, status, message):
                self.status = status
                self.message = message
        
        mock_exceptions = MagicMock()
        mock_exceptions.ServiceError = ServiceError
        
        mock_identity = MagicMock()
        mock_identity_client = MagicMock()
        mock_identity.IdentityClient.return_value = mock_identity_client
        
        mock_compute = MagicMock()
        mock_compute_client = MagicMock()
        mock_compute.ComputeClient.return_value = mock_compute_client
        
        mock_vcn = MagicMock()
        mock_vcn_client = MagicMock()
        mock_vcn.VirtualNetworkClient.return_value = mock_vcn_client
        
        mock_os = MagicMock()
        mock_os_client = MagicMock()
        mock_os.ObjectStorageClient.return_value = mock_os_client
        mock_os_client.get_namespace.return_value.data = "my-namespace"
        
        # Define behaviors:
        # list_users: success (ALLOWED)
        # list_instances: ServiceError 404 NotAuthorizedOrNotFound (DENIED)
        # list_vcns: ServiceError 401 (DENIED)
        # list_groups: other error (ERROR)
        
        def compute_list_instances(**kwargs):
            raise ServiceError(404, "NotAuthorizedOrNotFound")
            
        def vcn_list_vcns(**kwargs):
            raise ServiceError(401, "Unauthorized")
            
        def identity_list_groups(**kwargs):
            raise Exception("Some other error")
        
        mock_compute_client.list_instances.side_effect = compute_list_instances
        mock_vcn_client.list_vcns.side_effect = vcn_list_vcns
        mock_identity_client.list_groups.side_effect = identity_list_groups
        
        mock_oci = MagicMock()
        mock_oci.exceptions = mock_exceptions
        mock_oci.identity = mock_identity
        mock_oci.core = MagicMock()
        mock_oci.core.ComputeClient = mock_compute.ComputeClient
        mock_oci.core.VirtualNetworkClient = mock_vcn.VirtualNetworkClient
        mock_oci.object_storage = mock_os
        
        oci_mocks = {
            "oci": mock_oci,
            "oci.exceptions": mock_exceptions,
            "oci.identity": mock_identity,
            "oci.core": mock_oci.core,
            "oci.object_storage": mock_os
        }
        
        with patch.dict(sys.modules, oci_mocks):
            import importlib
            import quantum_mechanic.techniques.discovery.enum_permissions as mod
            importlib.reload(mod)
            result = mod.execute(mock_ctx)
            
        assert result["status"] == "success"
        assert result["method"] == "active_probing_list_apis"
        
        allowed = result["allowed_actions"]
        denied = result["denied_actions"]
        errors = result["errors"]
        
        assert "identity:list_users" in allowed
        assert "object_storage:list_buckets" in allowed
        
        assert "compute:list_instances" in denied
        assert "virtual_network:list_vcns" in denied
        
        assert any("identity:list_groups: Some other error" in e for e in errors)


# ================================================================
# Next Steps Coverage
# ================================================================
def test_generate_next_steps():
    from quantum_mechanic.techniques.discovery.enum_permissions import _generate_next_steps
    aws_steps = _generate_next_steps("aws", ["iam:PassRole", "ec2:RunInstances"])
    assert len(aws_steps) > 0
    azure_steps = _generate_next_steps("azure", ["microsoft.compute/virtualmachines/runcommand/action"])
    assert len(azure_steps) > 0
    gcp_steps = _generate_next_steps("gcp", ["iam.serviceAccounts.actAs", "compute.instances.create"])
    assert len(gcp_steps) > 0
    fallback = _generate_next_steps("aws", ["s3:ListAllMyBuckets"])
    assert len(fallback) == 1
