# ================================================================
# TESTS: lateral_movement/vm_execute_command
# ================================================================

import pytest
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.lateral_movement.vm_execute_command import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    # Mock property behavior for provider_name
    type(ctx).provider_name = ctx.provider_name
    return ctx

def test_aws_execute_command_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.get_param.side_effect = lambda x, default=None: {
        "target": "i-123",
        "cmd": "whoami"
    }.get(x, default)
    
    mock_ssm = MagicMock()
    mock_ctx.session.client.return_value = mock_ssm
    
    mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
    mock_ssm.get_command_invocation.return_value = {
        "Status": "Success",
        "StandardOutputContent": "root",
        "StandardErrorContent": ""
    }
    
    result = execute(mock_ctx)
    
    assert result["status"] == "Success"
    assert result["stdout"] == "root"
    mock_ssm.send_command.assert_called_once()

def test_azure_execute_command_success(mock_ctx):
    import sys
    mock_ctx.provider_name = "azure"
    # Full resource ID
    target_id = "/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v"
    mock_ctx.get_param.side_effect = lambda x, default=None: {
        "target": target_id,
        "cmd": "whoami",
        "shell": "bash"
    }.get(x, default)
    
    mock_compute = MagicMock()
    mock_compute_client = MagicMock()
    mock_compute.ComputeManagementClient.return_value = mock_compute_client
    
    # Mock result value with code and message
    mock_status = MagicMock()
    mock_status.code = "ComponentStatus/StdOut/succeeded"
    mock_status.message = "azure-user"
    
    mock_res = MagicMock()
    mock_res.value = [mock_status]
    mock_compute_client.virtual_machines.begin_run_command.return_value.result.return_value = mock_res
    
    # Mock models
    mock_models = MagicMock()
    
    mock_azure = MagicMock()
    mock_azure.mgmt.compute = mock_compute
    mock_azure.mgmt.compute.models = mock_models
    
    with patch.dict(sys.modules, {"azure.mgmt.compute": mock_azure.mgmt.compute, "azure.mgmt.compute.models": mock_models}):
        result = execute(mock_ctx)
        
    assert result["status"] == "Success"
    assert result["stdout"] == "azure-user"
