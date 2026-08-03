"""
Unit tests for discovery/enum_serverless.

Generated scaffold — fill in the mocks and assertions per cloud.
"""
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.techniques.discovery.enum_serverless import execute


# ---------------------------------------------------------------------------
# Happy path — one stub per provider
# ---------------------------------------------------------------------------
def test_aws_success():
    ctx = MagicMock()
    ctx.provider_name = 'aws'
    
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "eu-north-1"}]}
    
    mock_lambda = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Functions": [
            {
                "FunctionName": "api-lambda",
                "Role": "arn:aws:iam::123:role/lambda-role",
                "Runtime": "python3.12"
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
    # Assert the required contract fields — the technique also enriches with
    # env_var_count / env_vars / code_location which we don't want to lock down
    # here (future enrichment shouldn't break the test).
    assert len(result["functions"]) == 1
    fn = result["functions"][0]
    assert fn["name"] == "api-lambda"
    assert fn["role"] == "arn:aws:iam::123:role/lambda-role"
    assert fn["runtime"] == "python3.12"
    assert fn["region"] == "eu-north-1"

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


