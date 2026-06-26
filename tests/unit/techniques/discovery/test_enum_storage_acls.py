"""Smoke tests ensuring enum_storage_acls behaviour is preserved in enum_storage --public-only."""
import boto3
from unittest.mock import MagicMock, create_autospec

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.enum_storage import execute


def _make_ctx(public_only: bool = True):
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.provider_name = "aws"
    ctx.get_param.side_effect = lambda k: True if k == "public_only" and public_only else None
    ctx.session = create_autospec(boto3.Session, instance=True)
    ctx.workspace = MagicMock()
    return ctx


def test_aws_success():
    """OUTCOME: aws --public-only returns only publicly exposed buckets (mirrors old enum_storage_acls)."""
    ctx = _make_ctx()
    s3 = MagicMock()
    ctx.session.client.return_value = s3
    s3.list_buckets.return_value = {"Buckets": [
        {"Name": "open",   "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
        {"Name": "closed", "CreationDate": MagicMock(strftime=lambda f: "2024-01-01")},
    ]}

    def _acl(Bucket):
        if Bucket == "open":
            return {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}
        return {"Grants": []}
    s3.get_bucket_acl.side_effect = _acl
    s3.get_bucket_policy_status.side_effect = Exception("no policy")

    result = execute(ctx)
    assert result["total"] == 1
    assert result["buckets"][0]["name"] == "open"
    ctx.workspace.add_finding.assert_called_once()
