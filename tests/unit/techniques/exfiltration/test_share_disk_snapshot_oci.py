# ================================================================
# TESTS: exfiltration/share_disk_snapshot (OCI Path)
# ================================================================

import pytest
from unittest.mock import MagicMock, patch
import sys

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.exfiltration.share_disk_snapshot import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "oci"
    ctx.safe_mode = False
    ctx.session = {"config": {"tenancy": "ocid1.tenancy.oc1..test", "region": "us-ashburn-1"}}
    return ctx

def test_oci_exfil_success(mock_ctx):
    """Successfully create a boot volume backup in OCI."""
    mock_ctx.params = {"target_id": "ocid1.bootvolume.oc1..test"}
    
    # 1. Mock OCI SDK
    mock_storage = MagicMock()
    mock_storage_client = MagicMock()
    mock_storage.BlockstorageClient.return_value = mock_storage_client
    
    mock_resp = MagicMock()
    mock_resp.data.id = "ocid1.bootvolumebackup.oc1..test"
    mock_storage_client.create_boot_volume_backup.return_value = mock_resp
    
    # 2. Stub models
    class MockDetails:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
                
    mock_oci = MagicMock()
    mock_oci.core.BlockstorageClient = mock_storage.BlockstorageClient
    mock_oci.core.models.CreateBootVolumeBackupDetails = MockDetails
    
    with patch.dict(sys.modules, {"oci": mock_oci}):
        result = execute(mock_ctx)
        
    assert result["results"][0]["status"] == "Created"
    assert "ocid1.bootvolumebackup" in result["results"][0]["snapshot_id"]
    mock_storage_client.create_boot_volume_backup.assert_called_once()

def test_oci_exfil_missing_id(mock_ctx):
    """Fails if target_id is missing."""
    mock_ctx.params = {}
    res = execute(mock_ctx)
    assert "error" in res
    assert "requires 'target_id'" in res["error"]
