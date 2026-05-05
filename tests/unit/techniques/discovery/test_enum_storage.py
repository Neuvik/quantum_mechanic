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
