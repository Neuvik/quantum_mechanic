"""
Unit tests for discovery/enum_storage_acls.

Generated scaffold — fill in the mocks and assertions per cloud.
"""
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.techniques.discovery.enum_storage_acls import execute


# ---------------------------------------------------------------------------
# Happy path — one stub per provider
# ---------------------------------------------------------------------------
def test_aws_success():
    ctx = MagicMock()
    ctx.provider_name = 'aws'
    ctx.finding = MagicMock()
    
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {"Name": "public-bucket"},
            {"Name": "private-bucket"}
        ]
    }
    
    def get_bucket_acl_side_effect(Bucket):
        if Bucket == "public-bucket":
            return {
                "Grants": [
                    {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
                ]
            }
        else:
            return {"Grants": []}
            
    mock_s3.get_bucket_acl.side_effect = get_bucket_acl_side_effect
    
    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3
    ctx.session = mock_session
    
    result = execute(ctx)

    assert result["provider"] == "aws"
    assert result["total"] == 2          # all buckets returned, not just public ones
    assert result["vulnerable_count"] == 1  # only the public bucket flagged
    # Every bucket is in the list; public flag indicates exposure
    buckets_by_name = {b["name"]: b for b in result["buckets"]}
    assert buckets_by_name["public-bucket"]["public"] is True
    assert buckets_by_name["private-bucket"]["public"] is False
    # Finding is written via workspace.add_finding, not ctx.finding
    ctx.workspace.add_finding.assert_called_once()

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


