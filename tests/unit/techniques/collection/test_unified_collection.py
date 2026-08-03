# ================================================================
# TESTS: unified collection modules
# ================================================================

import pytest
import os
from unittest.mock import MagicMock, patch
from pathlib import Path
from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.collection.storage_search import execute as execute_storage
from quantum_mechanic.techniques.collection.scan_disk_content import execute as execute_disk
from quantum_mechanic.techniques.collection.unified_collection import execute as execute_unified

@pytest.fixture
def mock_ctx():
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "aws"
    ctx.safe_mode = False
    ctx.session = MagicMock()
    # Ensure get_param returns values from a dict, not a MagicMock
    ctx.params = {}
    ctx.get_param.side_effect = lambda x, default=None: ctx.params.get(x, default)
    
    # Mock subtask to return a new context
    @contextlib.contextmanager
    def mock_subtask(name, params=None):
        sub = MagicMock(spec=ExecutionContext)
        sub.provider_name = ctx.provider_name
        sub.session = ctx.session
        sub.params = ctx.params.copy()
        if params:
            sub.params.update(params)
        sub.get_param.side_effect = lambda x, default=None: sub.params.get(x, default)
        yield sub
        
    ctx.subtask.side_effect = mock_subtask
    return ctx

import contextlib

def test_unified_collection_all_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.params = {"mode": "all", "target": "my-bucket", "snapshot": "snap-123"}
    
    mock_s3 = MagicMock()
    mock_ebs = MagicMock()
    
    def get_client(service, **kwargs):
        if service == "s3": return mock_s3
        if service == "ebs": return mock_ebs
        return MagicMock()
        
    mock_ctx.session.client.side_effect = get_client
    
    # Mock S3 hits
    mock_s3.list_objects_v2.return_value = {
        "Contents": [{"Key": ".env", "Size": 100}]
    }
    
    # Mock EBS hits
    mock_ebs.list_snapshot_blocks.return_value = {"Blocks": [{"BlockIndex": 0, "BlockToken": "t1"}]}
    mock_data = MagicMock()
    mock_data.read.return_value = b"BEGIN RSA PRIVATE KEY"
    mock_ebs.get_snapshot_block.return_value = {"BlockData": mock_data}
    
    # Also mock EC2 for snapshot verification
    mock_ec2 = MagicMock()
    mock_ctx.session.client.side_effect = lambda s, **k: {"s3": mock_s3, "ebs": mock_ebs, "ec2": mock_ec2}[s]
    mock_ec2.describe_snapshots.return_value = {"Snapshots": [{"State": "completed", "Encrypted": False}]}

    result = execute_unified(mock_ctx)
    
    assert result["count"] == 2
    sources = [h["source"] for h in result["hits"]]
    assert "Object Storage" in sources
    assert "Disk/Snapshot" in sources

def test_scan_cloud_storage_aws_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.params = {"target": "my-bucket"}
    
    mock_s3 = MagicMock()
    mock_ctx.session.client.return_value = mock_s3
    mock_s3.list_objects_v2.return_value = {
        "Contents": [{"Key": ".env", "Size": 100}, {"Key": "image.jpg", "Size": 200}]
    }
    
    result = execute_storage(mock_ctx)
    assert len(result["hits"]) == 1
    assert result["hits"][0]["key"] == ".env"

def test_scan_disk_content_success(mock_ctx, tmp_path):
    # Create mock filesystem
    disk_dir = tmp_path / "mnt"
    disk_dir.mkdir()
    (disk_dir / ".env").write_text("DB_PASS=secret")
    (disk_dir / "id_rsa").write_text("private-key")
    (disk_dir / "normal.txt").write_text("nothing")
    
    mock_ctx.params = {"target": str(disk_dir), "snapshot": None}
    
    result = execute_disk(mock_ctx)
    
    # Sort hits for stable comparison
    paths = [Path(h["path"]).name for h in result["hits"]]
    assert ".env" in paths
    assert "id_rsa" in paths
    assert "normal.txt" not in paths
    assert result["count"] == 2

def test_scan_disk_content_aws_direct_success(mock_ctx):
    mock_ctx.provider_name = "aws"
    mock_ctx.params = {"snapshot": "snap-123", "target": None}
    
    mock_ebs = MagicMock()
    mock_ctx.session.client.return_value = mock_ebs
    
    mock_ebs.list_snapshot_blocks.return_value = {
        "Blocks": [{"BlockIndex": 0, "BlockToken": "t1"}]
    }
    
    # Mock the StreamingBody from GetSnapshotBlock
    mock_data = MagicMock()
    mock_data.read.return_value = b"some data here BEGIN RSA PRIVATE KEY end"
    mock_ebs.get_snapshot_block.return_value = {"BlockData": mock_data}

    # Mock EC2 for snapshot verification
    mock_ec2 = MagicMock()
    mock_ctx.session.client.side_effect = lambda s, **k: {"ebs": mock_ebs, "ec2": mock_ec2}[s]
    mock_ec2.describe_snapshots.return_value = {"Snapshots": [{"State": "completed", "Encrypted": False}]}
    
    result = execute_disk(mock_ctx)
    
    assert result["count"] == 1
    assert result["hits"][0]["label"] == "Direct Block Match"
    assert "BEGIN RSA PRIVATE KEY" in result["hits"][0]["type"]
