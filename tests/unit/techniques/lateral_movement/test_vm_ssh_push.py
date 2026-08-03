# ================================================================
# TESTS: lateral_movement/vm_ssh_push
# ================================================================

import pytest
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.lateral_movement.vm_ssh_push import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    # Mock property behavior for provider_name
    type(ctx).provider_name = ctx.provider_name
    return ctx

def test_gcp_ssh_push_success(mock_ctx):
    mock_ctx.provider_name = "gcp"
    mock_ctx.get_param.side_effect = lambda x, default=None: {
        "target": "vm-1",
        "pub": "ssh-rsa AAA",
        "user": "alice",
        "zone": "us-central1-a"
    }.get(x, default)
    mock_ctx.whoami.return_value.account_id = "proj-1"
    
    with patch("googleapiclient.discovery.build") as mock_build:
        mock_compute = MagicMock()
        mock_build.return_value = mock_compute
        
        mock_compute.instances().get().execute.return_value = {
            "metadata": {"fingerprint": "abc", "items": []}
        }
        
        result = execute(mock_ctx)
        
    assert result["status"] == "success"
    assert result["user"] == "alice"
    mock_compute.instances().setMetadata.assert_called_once()

def test_oci_ssh_push_success(mock_ctx):
    import sys
    mock_ctx.provider_name = "oci"
    mock_ctx.session = {"config": {"tenancy": "t"}, "signer": None}
    mock_ctx.get_param.side_effect = lambda x, default=None: {
        "target": "ocid1.instance.123",
        "pub": "ssh-rsa AAA",
        "user": "opc"
    }.get(x, default)
    
    mock_oci = MagicMock()
    mock_compute_client = MagicMock()
    mock_oci.core.ComputeClient.return_value = mock_compute_client
    
    mock_inst = MagicMock()
    mock_inst.metadata = {"ssh_authorized_keys": "old-key"}
    mock_compute_client.get_instance.return_value.data = mock_inst
    
    with patch.dict(sys.modules, {"oci": mock_oci}):
        result = execute(mock_ctx)
        
    assert result["status"] == "success"
    mock_compute_client.update_instance.assert_called_once()
