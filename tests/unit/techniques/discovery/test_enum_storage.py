"""
Unit tests for discovery/enum_storage.
"""
from unittest.mock import MagicMock, create_autospec, patch
import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.enum_storage import execute

# ================================================================
# AWS
# ================================================================

def test_returns_parsed_buckets_from_aws():
    """OUTCOME: Parses and returns list of buckets correctly when s3.list_buckets succeeds."""
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.session = MagicMock()
    ctx.provider_name = 'aws'
    ctx.get_param.return_value = ""  # No target

    s3 = MagicMock()
    s3.list_buckets.return_value = {
        "Buckets": [{"Name": "test-bucket-1", "CreationDate": "2024-01-01"}]
    }
    ctx.session.client.return_value = s3
    
    result = execute(ctx)
    assert result["provider"] == "aws"
    assert result.get("total") == 1
    assert result["buckets"][0]["name"] == "test-bucket-1"

# ================================================================
# Azure
# ================================================================

@patch.dict("sys.modules", {
    "azure.mgmt.storage": MagicMock(),
    "azure.mgmt.subscription": MagicMock(),
    "azure.identity": MagicMock(),
})
def test_returns_parsed_buckets_from_azure():
    """OUTCOME: Parses and returns list of storage accounts correctly when Azure SDK succeeds."""
    import sys
    mock_smc_cls = sys.modules["azure.mgmt.storage"].StorageManagementClient
    mock_sc_cls = sys.modules["azure.mgmt.subscription"].SubscriptionClient

    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.session = MagicMock()
    ctx.provider_name = 'azure'
    ctx.get_param.return_value = ""  # No target
    
    mock_sc = mock_sc_cls.return_value
    mock_sub = MagicMock()
    mock_sub.subscription_id = "sub-123"
    mock_sc.subscriptions.list.return_value = [mock_sub]
    
    mock_smc = mock_smc_cls.return_value
    mock_account = MagicMock()
    mock_account.name = "storageact1"
    mock_account.location = "eastus"
    # Fields added by implementation
    mock_account.access_tier = "Hot"
    mock_account.primary_endpoints.blob = "https://storageact1.blob.core.windows.net/"
    mock_account.creation_time = "2024-01-01"
    
    mock_smc.storage_accounts.list.return_value = [mock_account]
    
    result = execute(ctx)
    
    assert result["provider"] == "azure"
    assert result.get("total") == 1
    # Check key fields (implementation adds more)
    bucket = result["buckets"][0]
    assert bucket["name"] == "storageact1"
    assert bucket["location"] == "eastus"
    assert bucket["subscription_id"] == "sub-123"

# ================================================================
# GCP
# ================================================================

@patch.dict("sys.modules", {
    "googleapiclient.discovery": MagicMock(),
    "google.auth.credentials": MagicMock(),
})
def test_returns_parsed_buckets_from_gcp():
    """OUTCOME: Parses and returns list of buckets correctly when GCP API succeeds."""
    import sys
    mock_build = sys.modules["googleapiclient.discovery"].build

    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.session = MagicMock()
    ctx.provider_name = 'gcp'
    ctx.get_param.return_value = ""
    
    mock_whoami = MagicMock()
    mock_whoami.account_id = "test-project-id"
    ctx.whoami.return_value = mock_whoami
    
    mock_storage = MagicMock()
    mock_build.return_value = mock_storage
    mock_request = MagicMock()
    mock_request.execute.return_value = {
        "items": [
            {"name": "test-bucket-gcp", "location": "US"}
        ]
    }
    mock_storage.buckets.return_value.list.return_value = mock_request
    
    result = execute(ctx)
    assert result["provider"] == "gcp"
    assert result.get("total") == 1
    assert result["buckets"][0]["name"] == "test-bucket-gcp"

# ================================================================
# OCI
# ================================================================

@patch.dict("sys.modules", {"oci": MagicMock()})
def test_returns_parsed_buckets_from_oci():
    """OUTCOME: Parses and returns list of buckets correctly when OCI API succeeds."""
    import sys
    oci = sys.modules["oci"]

    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.session = MagicMock()
    ctx.provider_name = 'oci'
    ctx.get_param.return_value = ""
    
    mock_whoami = MagicMock()
    mock_whoami.tenancy_id = "ocid1.tenancy.123"
    ctx.whoami.return_value = mock_whoami
    
    mock_os = oci.object_storage.ObjectStorageClient.return_value
    mock_bucket = MagicMock()
    mock_bucket.name = "test-bucket-oci"
    mock_os.list_buckets.return_value.data = [mock_bucket]
    
    result = execute(ctx)
    assert result["provider"] == "oci"
    # In OCI it iterates tenancy and then compartments.
    # Simplified mock might return just the tenancy one or both.
    assert result.get("total") >= 1


# ================================================================
# --public-only flag
# ================================================================

import boto3

def _make_aws_ctx(public_only: bool = False):
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.provider_name = "aws"
    ctx.get_param.side_effect = lambda k: True if k == "public_only" and public_only else None
    ctx.session = create_autospec(boto3.Session, instance=True)
    ctx.workspace = MagicMock()
    return ctx


def test_aws_public_only_filters_to_exposed_buckets():
    """OUTCOME: --public-only returns only buckets with a non-empty public label.

    ANTI-GAMIFICATION: ctx.session is create_autospec(boto3.Session).
    Calling .get() on it raises AttributeError immediately (wrong interface).
    """
    ctx = _make_aws_ctx(public_only=True)
    s3 = MagicMock()
    ctx.session.client.return_value = s3
    s3.list_buckets.return_value = {"Buckets": [
        {"Name": "public-bucket",  "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
        {"Name": "private-bucket", "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
    ]}

    def mock_acl(Bucket):
        if Bucket == "public-bucket":
            return {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}
        return {"Grants": []}
    s3.get_bucket_acl.side_effect = mock_acl
    s3.get_bucket_policy_status.side_effect = Exception("no policy")

    result = execute(ctx)

    assert result["total"] == 1
    assert result["buckets"][0]["name"] == "public-bucket"
    assert "AllUsers" in result["buckets"][0]["public"]


def test_aws_public_only_writes_finding_for_exposed_bucket():
    """OUTCOME: each publicly exposed bucket produces one workspace finding."""
    ctx = _make_aws_ctx(public_only=True)
    s3 = MagicMock()
    ctx.session.client.return_value = s3
    s3.list_buckets.return_value = {"Buckets": [
        {"Name": "exposed", "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
    ]}
    s3.get_bucket_acl.return_value = {"Grants": [
        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
    ]}
    s3.get_bucket_policy_status.side_effect = Exception("no policy")

    execute(ctx)

    ctx.workspace.add_finding.assert_called_once()
    call_kwargs = ctx.workspace.add_finding.call_args.kwargs
    assert call_kwargs["severity"] == "high"
    assert "exposed" in call_kwargs["title"]


def test_aws_without_public_only_returns_all_buckets_no_findings():
    """OUTCOME: default (no --public-only) returns all buckets; no findings written."""
    ctx = _make_aws_ctx(public_only=False)
    s3 = MagicMock()
    ctx.session.client.return_value = s3
    s3.list_buckets.return_value = {"Buckets": [
        {"Name": "pub",  "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
        {"Name": "priv", "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
    ]}
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_policy_status.side_effect = Exception("no policy")

    result = execute(ctx)

    assert result["total"] == 2
    ctx.workspace.add_finding.assert_not_called()
