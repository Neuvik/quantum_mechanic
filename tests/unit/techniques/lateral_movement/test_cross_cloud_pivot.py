# ================================================================
# TESTS: lateral_movement/cross_cloud_pivot
# ================================================================

import pytest
import json
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.lateral_movement.cross_cloud_pivot import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    ctx.workspace = MagicMock()
    # We must ensure ctx.provider_name correctly returns from the property
    type(ctx).provider_name = ctx.provider_name # Allow manual setting
    return ctx

def test_aws_to_gcp_pivot_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.get_param.side_effect = lambda x, default=None: {
        "method": "aws_to_gcp",
        "target": "sa@proj.iam.gserviceaccount.com",
        "project": "123",
        "pool": "p1",
        "prov": "pr1"
    }.get(x, default)
    
    # Mock AWS session/creds
    mock_creds = MagicMock()
    mock_creds.get_frozen_credentials.return_value = MagicMock(access_key="AK", secret_key="SK", token=None)
    mock_ctx.session.get_credentials.return_value = mock_creds
    mock_ctx.session.region_name = "us-east-1"
    
    # Mock urllib.request.urlopen for Google STS and IAM
    mock_resp_sts = MagicMock()
    mock_resp_sts.read.return_value = json.dumps({"access_token": "fed-token"}).encode()
    mock_resp_sts.__enter__.return_value = mock_resp_sts
    
    mock_resp_iam = MagicMock()
    mock_resp_iam.read.return_value = json.dumps({"accessToken": "gcp-token"}).encode()
    mock_resp_iam.__enter__.return_value = mock_resp_iam
    
    with patch("urllib.request.urlopen") as mock_url:
        mock_url.side_effect = [mock_resp_sts, mock_resp_iam]
        result = execute(mock_ctx)
        print(f"DEBUG PIVOT RESULT: {result}")
        
    assert result["results"][0]["status"] == "Pivoted & Imported"
    assert result["results"][0]["identity"] == "sa@proj.iam.gserviceaccount.com"
    mock_ctx.workspace.add_credential.assert_called_once()
