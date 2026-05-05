# ================================================================
# TESTS: discovery/enum_snapshots
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, call, create_autospec, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.enum_snapshots import (
    _enum_amis,
    _enum_snapshots,
    _resolve_regions,
    _snapshot_is_public,
    execute,
)


def _ctx(params: dict | None = None) -> MagicMock:
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.provider_name = "aws"
    ctx.params = params or {}
    ctx.get_param.side_effect = lambda name, default=None: ctx.params.get(name, default)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    ctx.info = MagicMock()
    return ctx


# ================================================================
# Region resolution
# ================================================================

class TestResolveRegions:
    def test_explicit_single_region(self):
        ctx = _ctx(params={"region": "us-east-1"})
        assert _resolve_regions(ctx) == ["us-east-1"]

    def test_explicit_comma_list(self):
        ctx = _ctx(params={"region": "us-east-1,eu-west-1"})
        assert _resolve_regions(ctx) == ["us-east-1", "eu-west-1"]

    def test_default_calls_describe_regions_with_filter(self):
        ctx = _ctx(params={})
        ctx.session.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]
        }
        regions = _resolve_regions(ctx, session=ctx.session)
        assert regions == ["us-east-1", "eu-west-1"]
        call_kwargs = ctx.session.client.return_value.describe_regions.call_args
        assert "Filters" in call_kwargs.kwargs or "Filters" in (call_kwargs.args[0] if call_kwargs.args else {})

    def test_all_calls_describe_regions_all_regions(self):
        ctx = _ctx(params={"region": "all"})
        ctx.session.client.return_value.describe_regions.return_value = {
            "Regions": [{"RegionName": "ap-east-1"}]
        }
        regions = _resolve_regions(ctx, session=ctx.session)
        assert regions == ["ap-east-1"]
        ctx.session.client.return_value.describe_regions.assert_called_once_with(AllRegions=True)

    def test_api_failure_falls_back_to_us_east_1(self):
        from botocore.exceptions import ClientError
        ctx = _ctx(params={})
        ctx.session.client.return_value.describe_regions.side_effect = ClientError(
            {"Error": {"Code": "AuthFailure", "Message": "x"}}, "DescribeRegions"
        )
        regions = _resolve_regions(ctx, session=ctx.session)
        assert regions == ["us-east-1"]


# ================================================================
# _snapshot_is_public
# ================================================================

class TestSnapshotIsPublic:
    def test_group_all_returns_true(self):
        ec2 = MagicMock()
        ec2.describe_snapshot_attribute.return_value = {
            "CreateVolumePermissions": [{"Group": "all"}]
        }
        assert _snapshot_is_public(ec2, "snap-123") is True

    def test_no_public_grant_returns_false(self):
        ec2 = MagicMock()
        ec2.describe_snapshot_attribute.return_value = {
            "CreateVolumePermissions": [{"UserId": "123456789012"}]
        }
        assert _snapshot_is_public(ec2, "snap-123") is False

    def test_empty_permissions_returns_false(self):
        ec2 = MagicMock()
        ec2.describe_snapshot_attribute.return_value = {"CreateVolumePermissions": []}
        assert _snapshot_is_public(ec2, "snap-123") is False

    def test_api_error_returns_false(self):
        ec2 = MagicMock()
        ec2.describe_snapshot_attribute.side_effect = Exception("AccessDenied")
        assert _snapshot_is_public(ec2, "snap-123") is False


# ================================================================
# _enum_snapshots
# ================================================================

class TestEnumSnapshots:
    def _make_ec2(self, snapshots, public_snap_ids=None):
        ec2 = MagicMock()
        public_snap_ids = public_snap_ids or set()

        paginator = MagicMock()
        paginator.__iter__ = MagicMock(return_value=iter([{"Snapshots": snapshots}]))
        paginator.paginate.return_value = [{"Snapshots": snapshots}]
        ec2.get_paginator.return_value = paginator

        def _attr(SnapshotId, Attribute):
            perms = [{"Group": "all"}] if SnapshotId in public_snap_ids else []
            return {"CreateVolumePermissions": perms}

        ec2.describe_snapshot_attribute.side_effect = _attr
        return ec2

    def test_public_snapshot_flagged(self):
        snap = {"SnapshotId": "snap-public", "State": "completed", "VolumeSize": 20,
                "Encrypted": False, "Description": "test", "StartTime": "2024-01-01",
                "VolumeId": "vol-1", "OwnerId": "123"}
        ec2 = self._make_ec2([snap], public_snap_ids={"snap-public"})
        results = _enum_snapshots(ec2, "us-east-1")
        assert len(results) == 1
        assert results[0]["public"] is True
        assert results[0]["region"] == "us-east-1"

    def test_private_snapshot_not_flagged(self):
        snap = {"SnapshotId": "snap-private", "State": "completed", "VolumeSize": 10,
                "Encrypted": True, "Description": "", "StartTime": "2024-01-01",
                "VolumeId": "vol-2", "OwnerId": "123"}
        ec2 = self._make_ec2([snap])
        results = _enum_snapshots(ec2, "us-east-1")
        assert results[0]["public"] is False
        assert results[0]["encrypted"] is True


# ================================================================
# _enum_amis
# ================================================================

class TestEnumAmis:
    def test_public_ami_flagged(self):
        ec2 = MagicMock()
        ec2.describe_images.return_value = {"Images": [{
            "ImageId": "ami-public",
            "Public": True,
            "State": "available",
            "Name": "my-ami",
            "Description": "test",
            "CreationDate": "2024-01-01",
            "OwnerId": "123",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [{"Ebs": {"VolumeSize": 8, "Encrypted": False}}],
        }]}
        results = _enum_amis(ec2, "us-east-1")
        assert results[0]["public"] is True
        assert results[0]["type"] == "ami"
        assert results[0]["size_gb"] == 8

    def test_private_ami_not_flagged(self):
        ec2 = MagicMock()
        ec2.describe_images.return_value = {"Images": [{
            "ImageId": "ami-private",
            "Public": False,
            "State": "available",
            "Name": "private-ami",
            "CreationDate": "2024-01-01",
            "OwnerId": "123",
            "Architecture": "arm64",
            "BlockDeviceMappings": [],
        }]}
        results = _enum_amis(ec2, "us-east-1")
        assert results[0]["public"] is False


# ================================================================
# execute — integration
# ================================================================

class TestExecute:
    def test_returns_snapshots_key(self):
        ctx = _ctx(params={"region": "us-east-1"})
        ec2 = MagicMock()
        ctx.session.client.return_value = ec2
        ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": []}]
        ec2.describe_images.return_value = {"Images": []}

        result = execute(ctx)
        assert "snapshots" in result
        assert "total" in result
        assert "regions_scanned" in result

    def test_public_count_in_result(self):
        ctx = _ctx(params={"region": "us-east-1"})
        ec2 = MagicMock()
        ctx.session.client.return_value = ec2

        ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": [{
            "SnapshotId": "snap-pub", "State": "completed", "VolumeSize": 20,
            "Encrypted": False, "Description": "", "StartTime": "2024",
            "VolumeId": "vol-1", "OwnerId": "123",
        }]}]
        ec2.describe_snapshot_attribute.return_value = {
            "CreateVolumePermissions": [{"Group": "all"}]
        }
        ec2.describe_images.return_value = {"Images": []}

        result = execute(ctx)
        assert result["public_count"] == 1

    def test_unknown_provider_not_applicable(self):
        # enum_snapshots is AWS-only; other providers handled by runner
        ctx = _ctx(params={"region": "us-east-1"})
        ctx.provider_name = "azure"
        # session still mocked as AWS — just verify it doesn't crash
        ec2 = MagicMock()
        ctx.session.client.return_value = ec2
        ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": []}]
        ec2.describe_images.return_value = {"Images": []}
        result = execute(ctx)
        assert isinstance(result, dict)


# ================================================================
# Anonymous mode
# ================================================================

class TestAnonymousMode:
    def test_no_account_or_search_returns_error(self):
        ctx = _ctx(params={})
        ctx.session = None
        result = execute(ctx)
        assert "error" in result
        assert "account_id" in result["error"] or "search" in result["error"]

    @patch("quantum_mechanic.techniques.discovery.enum_snapshots.boto3")
    def test_anonymous_with_account_id(self, mock_boto3):
        ec2 = MagicMock()
        mock_boto3.client.return_value = ec2
        ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": [{
            "SnapshotId": "snap-pub", "State": "completed", "VolumeSize": 20,
            "Encrypted": False, "Description": "prod backup", "StartTime": "2024",
            "OwnerId": "123456789012",
        }]}]
        ec2.describe_images.return_value = {"Images": []}

        ctx = _ctx(params={"account_id": "123456789012", "region": "us-east-1"})
        ctx.session = None
        result = execute(ctx)

        assert result["mode"] == "anonymous"
        assert result["total"] >= 1
        assert all(s["public"] for s in result["snapshots"])

    @patch("quantum_mechanic.techniques.discovery.enum_snapshots.boto3")
    def test_anonymous_with_search(self, mock_boto3):
        ec2 = MagicMock()
        mock_boto3.client.return_value = ec2
        ec2.get_paginator.return_value.paginate.return_value = [{"Snapshots": []}]
        ec2.describe_images.return_value = {"Images": []}

        ctx = _ctx(params={"search": "prod", "region": "us-east-1"})
        ctx.session = None
        result = execute(ctx)

        assert result["mode"] == "anonymous"
        assert "error" not in result


class TestResolveRegionsNoSession:
    def test_no_session_returns_common_regions(self):
        from quantum_mechanic.techniques.discovery.enum_snapshots import (
            _COMMON_REGIONS,
            _resolve_regions,
        )
        ctx = _ctx(params={})
        ctx.session = None
        regions = _resolve_regions(ctx, session=None)
        assert regions == _COMMON_REGIONS

    def test_explicit_region_works_without_session(self):
        from quantum_mechanic.techniques.discovery.enum_snapshots import _resolve_regions
        ctx = _ctx(params={"region": "eu-west-1"})
        ctx.session = None
        assert _resolve_regions(ctx, session=None) == ["eu-west-1"]
