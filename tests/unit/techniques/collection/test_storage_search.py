# ================================================================
# TESTS: collection/storage_search
# ================================================================

import pytest
from unittest.mock import MagicMock, patch
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.collection.storage_search import execute

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "aws"
    ctx.safe_mode = False
    ctx.session = MagicMock()
    # Ensure get_param returns values from a dict, not a MagicMock
    ctx.params = {}
    ctx.get_param.side_effect = lambda x, default=None: ctx.params.get(x, default)
    return ctx

def test_aws_storage_search_hits(mock_ctx):
    """Successfully find sensitive files in S3 buckets."""
    mock_ctx.params = {}
    
    mock_s3 = MagicMock()
    mock_ctx.session.client.return_value = mock_s3
    
    # 1. Mock list_buckets
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "public-bucket"}, {"Name": "private-data"}]
    }
    
    # 2. Mock list_objects_v2
    def mock_list_objects(Bucket, **kwargs):
        if Bucket == "public-bucket":
            return {
                "Contents": [
                    {"Key": "index.html", "Size": 100},
                    {"Key": ".env", "Size": 500},
                ]
            }
        else:
            return {
                "Contents": [
                    {"Key": "backup.zip", "Size": 10000},
                    {"Key": "notes.txt", "Size": 50},
                ]
            }
            
    mock_s3.list_objects_v2.side_effect = mock_list_objects
    
    result = execute(mock_ctx)
    
    assert result["count"] == 2
    keys = [h["key"] for h in result["hits"]]
    assert ".env" in keys
    assert "backup.zip" in keys
    assert "index.html" not in keys

def test_aws_storage_search_targeted(mock_ctx):
    """Search only a specific bucket if provided."""
    mock_ctx.params = {"target": "only-this-one"}
    
    mock_s3 = MagicMock()
    mock_ctx.session.client.return_value = mock_s3
    
    mock_s3.list_objects_v2.return_value = {
        "Contents": [{"Key": "id_rsa", "Size": 1600}]
    }
    
    result = execute(mock_ctx)
    
    assert result["count"] == 1
    assert result["hits"][0]["bucket"] == "only-this-one"
    mock_s3.list_buckets.assert_not_called()

def test_aws_storage_search_custom_regex(mock_ctx):
    """Use custom regex if provided."""
    mock_ctx.params = {"regex": r"critical-.*\.pdf"}
    
    mock_s3 = MagicMock()
    mock_ctx.session.client.return_value = mock_s3
    mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
    mock_s3.list_objects_v2.return_value = {
        "Contents": [
            {"Key": ".env", "Size": 10},  # should NOT match now
            {"Key": "critical-data.pdf", "Size": 500}, # should match
        ]
    }
    
    result = execute(mock_ctx)
    assert result["count"] == 1
    assert result["hits"][0]["key"] == "critical-data.pdf"

def test_azure_storage_search_success(mock_ctx):
    """Verify Azure storage search logic and SDK calls."""
    import sys
    mock_ctx.provider_name = "azure"
    mock_ctx.params = {}
    
    # 1. Setup mocks
    mock_sub_client = MagicMock()
    sub = MagicMock()
    sub.subscription_id = "sub-1"
    mock_sub_client.subscriptions.list.return_value = [sub]
    
    mock_mgmt_client = MagicMock()
    acc = MagicMock()
    acc.name = "mystorage"
    mock_mgmt_client.storage_accounts.list.return_value = [acc]
    
    mock_blob_client = MagicMock()
    cont = MagicMock()
    cont.name = "mycontainer"
    mock_blob_client.list_containers.return_value = [cont]
    
    blob = MagicMock()
    blob.name = ".env"
    blob.size = 123
    mock_cont_client = MagicMock()
    mock_cont_client.list_blobs.return_value = [blob]
    mock_blob_client.get_container_client.return_value = mock_cont_client

    # 2. Patch the entire module structure
    azure_mocks = {
        "azure.mgmt.subscription": MagicMock(),
        "azure.mgmt.storage": MagicMock(),
        "azure.storage.blob": MagicMock()
    }
    azure_mocks["azure.mgmt.subscription"].SubscriptionClient = MagicMock(return_value=mock_sub_client)
    azure_mocks["azure.mgmt.storage"].StorageManagementClient = MagicMock(return_value=mock_mgmt_client)
    azure_mocks["azure.storage.blob"].BlobServiceClient = MagicMock(return_value=mock_blob_client)

    with patch.dict(sys.modules, azure_mocks):
        result = execute(mock_ctx)
    
    assert result["count"] == 1
    assert result["hits"][0]["key"] == ".env"
    assert result["hits"][0]["bucket"] == "mystorage/mycontainer"

def test_gcp_storage_search_success(mock_ctx):
    """Verify GCP storage search logic and API calls."""
    mock_ctx.provider_name = "gcp"
    mock_ctx.params = {}
    mock_ctx.whoami.return_value.account_id = "my-project"
    
    with patch("googleapiclient.discovery.build") as mock_build:
        mock_storage = MagicMock()
        mock_build.return_value = mock_storage
        
        # Mock Buckets
        mock_storage.buckets().list().execute.return_value = {
            "items": [{"name": "my-bucket"}]
        }
        
        # Mock Objects
        mock_storage.objects().list().execute.return_value = {
            "items": [{"name": "config.json", "size": "456"}, {"name": "image.png", "size": "1000"}]
        }
        
        result = execute(mock_ctx)
        
        assert result["count"] == 1
        assert result["hits"][0]["key"] == "config.json"
        assert result["hits"][0]["bucket"] == "my-bucket"

def test_oci_storage_search_success(mock_ctx):
    """Verify OCI storage search logic and SDK calls."""
    import sys
    mock_ctx.provider_name = "oci"
    mock_ctx.params = {}
    mock_ctx.session = {"config": {"tenancy": "ten-123", "region": "us-ashburn-1"}}
    
    mock_identity = MagicMock()
    mock_identity_client = MagicMock()
    mock_identity.IdentityClient.return_value = mock_identity_client
    mock_identity_client.list_compartments.return_value.data = []
    
    mock_os = MagicMock()
    mock_os_client = MagicMock()
    mock_os.ObjectStorageClient.return_value = mock_os_client
    mock_os_client.get_namespace.return_value.data = "ns-123"
    
    bucket = MagicMock()
    bucket.name = "my-bucket"
    mock_os_client.list_buckets.return_value.data = [bucket]
    
    obj = MagicMock()
    obj.name = "id_rsa"
    obj.size = 1600
    
    mock_objects_resp = MagicMock()
    mock_objects_resp.objects = [obj]
    mock_os_client.list_objects.return_value.data = mock_objects_resp
    
    mock_oci = MagicMock()
    mock_oci.identity = mock_identity
    mock_oci.object_storage = mock_os
    
    with patch.dict(sys.modules, {"oci": mock_oci}):
        result = execute(mock_ctx)
        
    assert result["count"] == 1
    assert result["hits"][0]["key"] == "id_rsa"
    assert result["hits"][0]["bucket"] == "my-bucket"
