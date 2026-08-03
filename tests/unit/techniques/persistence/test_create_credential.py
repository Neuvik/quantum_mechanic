# ================================================================
# TESTS: persistence/create_credential
# ================================================================

import pytest
import json
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.persistence.create_credential import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    ctx.workspace = MagicMock()
    ctx.params = {}
    ctx.get_param.side_effect = lambda name, default="": ctx.params.get(name, default)
    # We must ensure ctx.provider_name correctly returns from the property
    type(ctx).provider_name = ctx.provider_name # Allow manual setting
    return ctx

def test_aws_create_credential_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.params = {"target": "test-user"}
    
    mock_iam = MagicMock()
    mock_ctx.session.client.return_value = mock_iam
    mock_iam.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "AKIA123", "SecretAccessKey": "SECRET"}
    }
    
    result = execute(mock_ctx)
    print(f"DEBUG AWS RESULT: {result}")
    
    assert result["results"][0]["status"] == "Created"
    assert result["results"][0]["credential"] == "AKIA123"
    mock_ctx.workspace.add_credential.assert_called_once()

def test_gcp_create_credential_success(mock_ctx):
    mock_ctx.provider_name = "gcp"
    mock_ctx.params = {"target": "sa@project.iam.gserviceaccount.com"}
    
    with patch("googleapiclient.discovery.build") as mock_build:
        mock_iam = MagicMock()
        mock_build.return_value = mock_iam
        
        # Base64 encoded JSON key: {"project_id": "proj-1"} -> eyJwcm9qZWN0X2lkIjogInByb2otMSJ9
        mock_iam.projects().serviceAccounts().keys().create().execute.return_value = {
            "name": "projects/-/serviceAccounts/sa@project/keys/key-123",
            "privateKeyData": "eyJwcm9qZWN0X2lkIjogInByb2otMSJ9"
        }
        
        result = execute(mock_ctx)
        
    assert result["results"][0]["status"] == "Created"
    assert result["results"][0]["credential"] == "key-123"
    mock_ctx.workspace.add_credential.assert_called_once()

def test_azure_create_credential_success(mock_ctx):
    import sys
    import urllib.request
    from quantum_mechanic.providers.base import WhoAmIResult
    mock_ctx.provider_name = "azure"
    mock_ctx.params = {"target": "app-obj-id"}
    
    # Use a real object with string fields to avoid JSON serialization errors
    mock_who = WhoAmIResult(
        provider="azure",
        principal_id="user-123",
        account_id="acc-123",
        tenant_id="tenant-123",
        principal_type="user",
        friendly_name="Alice"
    )
    mock_ctx.whoami.return_value = mock_who
    
    mock_token = MagicMock()
    mock_token.token = "fake-token"
    mock_ctx.session.get_token.return_value = mock_token
    
    # Mock urllib.request.urlopen
    mock_resp_secret = MagicMock()
    # Ensure read() returns bytes for json.loads(bytes.decode())
    mock_resp_secret.read.return_value = json.dumps({"secretText": "val-123", "keyId": "k-123"}).encode()
    # Mock context manager behavior
    mock_resp_secret.__enter__.return_value = mock_resp_secret
    
    mock_resp_app = MagicMock()
    mock_resp_app.read.return_value = json.dumps({"appId": "client-id", "displayName": "my-app"}).encode()
    mock_resp_app.__enter__.return_value = mock_resp_app
    
    with patch("urllib.request.urlopen") as mock_url:
        mock_url.side_effect = [mock_resp_secret, mock_resp_app]
        result = execute(mock_ctx)
        print(f"DEBUG AZURE RESULT: {result}")
        
    assert result["results"][0]["status"] == "Created"
    assert result["results"][0]["secret"] == "val-123"
    mock_ctx.workspace.add_credential.assert_called_once()
