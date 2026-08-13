# ================================================================
# TESTS: core parameter validation
# ================================================================

import pytest
from unittest.mock import MagicMock
from quantum_mechanic.core.runner import TechniqueRunner, TechniqueResult
from quantum_mechanic.core.technique import Parameter, ParameterType, TechniqueMetadata

def test_parameter_validation_required_missing():
    """Verify that the runner fails when a required parameter is missing."""
    mock_workspace = MagicMock()
    mock_loader = MagicMock()
    mock_registry = MagicMock()
    
    # Mock a technique with a required parameter
    meta = TechniqueMetadata(
        id="test/tech",
        tactic="Discovery",
        providers=["aws"],
        parameters=[Parameter("target", "Target ID", required=True)]
    )
    mock_tech = MagicMock()
    mock_tech.metadata = meta
    mock_loader.get.return_value = mock_tech
    
    # Mock a credential
    mock_cred = MagicMock()
    mock_cred.provider = "aws"
    mock_workspace.get_credential.return_value = mock_cred
    mock_workspace.active_credential_id = 1
    
    runner = TechniqueRunner(mock_workspace, mock_loader, mock_registry)
    
    # Run with empty params
    result = runner.run("test/tech", params={})
    
    assert result.status == "error"
    assert "Missing required parameter: 'target'" in result.error

def test_parameter_validation_type_conversion(tmp_path):
    """Verify that the runner converts types according to the schema."""
    mock_workspace = MagicMock()
    mock_workspace.workspace_dir = tmp_path
    mock_loader = MagicMock()
    mock_registry = MagicMock()
    
    meta = TechniqueMetadata(
        id="test/tech",
        tactic="Discovery",
        providers=["aws"],
        parameters=[Parameter("count", "Count", type=ParameterType.INTEGER)]
    )
    mock_tech = MagicMock()
    mock_tech.metadata = meta
    
    # Capture the context passed to the function
    captured_ctx = None
    def mock_func(ctx):
        nonlocal captured_ctx
        captured_ctx = ctx
        return {"results": []}
    
    mock_tech.function = mock_func
    mock_loader.get.return_value = mock_tech
    
    mock_cred = MagicMock()
    mock_cred.provider = "aws"
    mock_cred.id = 1
    mock_workspace.get_credential.return_value = mock_cred
    mock_workspace.active_credential_id = 1
    
    # Mock provider authentication
    mock_provider = MagicMock()
    mock_registry.get.return_value = mock_provider
    mock_provider.authenticate.return_value = {}
    mock_workspace.get_credential_secret.return_value = "{}"
    
    runner = TechniqueRunner(mock_workspace, mock_loader, mock_registry)
    
    # Run with string '5' for integer param
    runner.run("test/tech", params={"count": "5"})
    
    assert captured_ctx.get_param("count") == 5
    assert isinstance(captured_ctx.get_param("count"), int)
