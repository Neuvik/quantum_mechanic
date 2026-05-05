"""
Unit tests for credential_access/serverless_env_harvest.

Generated scaffold — fill in the mocks and assertions per cloud.
"""
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.techniques.credential_access.serverless_env_harvest import execute


# ---------------------------------------------------------------------------
# Happy path — one stub per provider
# ---------------------------------------------------------------------------
def test_aws_success():
    ctx = MagicMock()
    ctx.provider_name = 'aws'
    ctx.finding = MagicMock()
    
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-west-2"}]}
    
    mock_lambda = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Functions": [
            {
                "FunctionName": "api-lambda",
                "Environment": {"Variables": {"DB_PASS": "super_secret"}}
            },
            {
                "FunctionName": "clean-lambda",
                "Environment": {}
            }
        ]
    }]
    mock_lambda.get_paginator.return_value = mock_paginator
    
    def client_side_effect(service_name, **kwargs):
        if service_name == "ec2":
            return mock_ec2
        elif service_name == "lambda":
            return mock_lambda
        return MagicMock()
    
    mock_session = MagicMock()
    mock_session.client.side_effect = client_side_effect
    ctx.session = mock_session
    
    result = execute(ctx)
    
    assert result["provider"] == "aws"
    assert result["total"] == 1
    assert result["vulnerable_functions"] == [{
        "name": "api-lambda",
        "env": {"DB_PASS": "super_secret"},
        "region": "us-west-2"
    }]
    ctx.finding.assert_called_once()

def test_azure_success():
    ctx = MagicMock()
    ctx.provider_name = 'azure'
    # TODO: configure ctx mocks for the azure path
    # execute(ctx)
    # ctx.finding.assert_called_once()
    pytest.skip("not implemented yet — fill in mocks")

def test_gcp_success():
    ctx = MagicMock()
    ctx.provider_name = 'gcp'
    # TODO: configure ctx mocks for the gcp path
    # execute(ctx)
    # ctx.finding.assert_called_once()
    pytest.skip("not implemented yet — fill in mocks")

def test_oci_success():
    ctx = MagicMock()
    ctx.provider_name = 'oci'
    # TODO: configure ctx mocks for the oci path
    # execute(ctx)
    # ctx.finding.assert_called_once()
    pytest.skip("not implemented yet — fill in mocks")


