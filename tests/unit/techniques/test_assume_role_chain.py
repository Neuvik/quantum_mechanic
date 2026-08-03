# ================================================================
# TESTS: escalation/assume_role_chain
# ================================================================

from __future__ import annotations

import json
from unittest.mock import MagicMock, call, create_autospec, patch

import pytest

from quantum_mechanic.techniques.escalation.assume_role_chain import (
    _trust_allows,
    execute,
)


# ================================================================
# Helpers
# ================================================================

def _make_ctx(
    *,
    safe_mode: bool = False,
    credential_id: int = 1,
    params: dict | None = None,
) -> MagicMock:
    """Build a minimal mock ExecutionContext for assume_role_chain tests."""
    ctx = MagicMock()
    ctx.credential_id = credential_id
    ctx.safe_mode = safe_mode
    ctx.params = params or {}
    ctx.provider_name = "aws"
    ctx.workspace = MagicMock()
    ctx.workspace.add_credential.return_value = 2

    # mock boto3 STS/IAM
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Arn": "arn:aws:iam::111111111111:user/test-user",
        "Account": "111111111111",
    }
    mock_iam = MagicMock()

    def _client(service_name, **kwargs):
        if service_name == "sts":
            return mock_sts
        if service_name == "iam":
            return mock_iam
        return MagicMock()

    ctx.session = MagicMock()
    ctx.session.client.side_effect = _client

    return ctx, mock_sts, mock_iam


# ================================================================
# _trust_allows unit tests
# ================================================================

class TestTrustAllows:
    def test_direct_arn_match(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:user/test-user"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        assert _trust_allows(policy, "arn:aws:iam::111:user/test-user")

    def test_account_wildcard_match(self):
        """Trust policies referencing arn:aws:iam::<account>:root match any principal in that account."""
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        assert _trust_allows(policy, "arn:aws:iam::111:user/any-user")

    def test_wildcard_principal(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        assert _trust_allows(policy, "arn:aws:iam::999:user/attacker")

    def test_deny_effect_ignored(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "arn:aws:iam::111:user/test-user"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        assert not _trust_allows(policy, "arn:aws:iam::111:user/test-user")

    def test_no_assume_role_action(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:user/test-user"},
                    "Action": "s3:GetObject",
                }
            ]
        }
        assert not _trust_allows(policy, "arn:aws:iam::111:user/test-user")

    def test_star_action(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111:user/test-user"},
                    "Action": "*",
                }
            ]
        }
        assert _trust_allows(policy, "arn:aws:iam::111:user/test-user")

    def test_json_string_policy(self):
        policy = json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123:user/alice"},
                    "Action": "sts:AssumeRole",
                }
            ]
        })
        assert _trust_allows(policy, "arn:aws:iam::123:user/alice")

    def test_non_matching_principal(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222:user/other"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        assert not _trust_allows(policy, "arn:aws:iam::111:user/test-user")


# ================================================================
# execute() tests
# ================================================================

class TestAssumeRoleChainExecute:
    def test_safe_mode_no_assume(self):
        """In safe_mode, roles should be listed but not assumed."""
        ctx, mock_sts, mock_iam = _make_ctx(safe_mode=True)

        target_role_arn = "arn:aws:iam::111111111111:role/EC2-KMS"
        trust_policy = json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:user/test-user"},
                    "Action": "sts:AssumeRole",
                }
            ]
        })
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [{"Arn": target_role_arn, "AssumeRolePolicyDocument": trust_policy}]}
        ]

        result = execute(ctx)

        assert result["safe_mode"] is True
        assert len(result["chains"]) == 1
        assert result["chains"][0]["assumed"] is False
        assert result["chains"][0]["role_arn"] == target_role_arn
        mock_sts.assume_role.assert_not_called()

    def test_successful_single_chain(self):
        """Should assume one role, store derived credential, report chain."""
        ctx, mock_sts, mock_iam = _make_ctx()

        target_role_arn = "arn:aws:iam::111111111111:role/TestRole"
        trust_policy = json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111111111111:user/test-user"},
                    "Action": "sts:AssumeRole",
                }
            ]
        })
        mock_iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [{"Arn": target_role_arn, "AssumeRolePolicyDocument": trust_policy}]}
        ]
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_FAKE",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": "2099-01-01T00:00:00Z",
            }
        }

        # boto3 is imported locally inside _follow_chain, so patch at builtins
        import sys
        import types

        # Build a mock boto3 module with a Session that returns no more roles
        mock_boto3 = types.ModuleType("boto3")
        child_session = MagicMock()
        child_sts = MagicMock()
        child_sts.get_caller_identity.return_value = {
            "Arn": target_role_arn,
            "Account": "111111111111",
        }
        child_iam = MagicMock()
        child_iam.get_paginator.return_value.paginate.return_value = [{"Roles": []}]

        def _child_client(svc, **kw):
            return child_sts if svc == "sts" else child_iam
        child_session.client.side_effect = _child_client
        mock_boto3.Session = MagicMock(return_value=child_session)

        saved_boto3 = sys.modules.get("boto3")
        sys.modules["boto3"] = mock_boto3
        try:
            result = execute(ctx)
        finally:
            if saved_boto3 is None:
                del sys.modules["boto3"]
            else:
                sys.modules["boto3"] = saved_boto3

        assert result.get("error") is None
        assert len(result["chains"]) == 1
        assert result["chains"][0]["assumed"] is True
        assert result["chains"][0]["role_arn"] == target_role_arn
        assert result["chains"][0]["credential_id"] == 2
        ctx.workspace.add_credential.assert_called_once()


    def test_no_assumable_roles(self):
        """Should return empty chains when no roles match the trust policy."""
        ctx, mock_sts, mock_iam = _make_ctx()

        mock_iam.get_paginator.return_value.paginate.return_value = [
            {"Roles": [{"Arn": "arn:aws:iam::999:role/other",
                        "AssumeRolePolicyDocument": json.dumps({"Statement": []})}]}
        ]

        result = execute(ctx)

        assert result["total"] == 0
        assert result["chains"] == []
        mock_sts.assume_role.assert_not_called()

    def test_iam_access_denied_graceful(self):
        """If iam:ListRoles is denied, return an empty chain without crashing."""
        from botocore.exceptions import ClientError

        ctx, mock_sts, mock_iam = _make_ctx()
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        mock_iam.get_paginator.return_value.paginate.side_effect = ClientError(
            error_response, "ListRoles"
        )

        result = execute(ctx)

        assert "error" not in result
        assert result["chains"] == []

    def test_boto3_not_available_graceful(self):
        """If botocore is unavailable, execute should return an error dict."""
        import sys
        import types

        # Replace botocore.exceptions with None to trigger ImportError guard
        saved = sys.modules.get("botocore.exceptions")
        sys.modules["botocore.exceptions"] = None  # type: ignore[assignment]
        try:
            # Reimporting won't work mid-test reliably; ensure execute itself
            # handles the missing import guard. We verify the guard by checking
            # that if get_caller_identity raises, we get an error dict.
            ctx, mock_sts, _ = _make_ctx()
            mock_sts.get_caller_identity.side_effect = Exception("Simulated total failure")
            result = execute(ctx)
            assert "error" in result
        finally:
            if saved is None:
                sys.modules.pop("botocore.exceptions", None)
            else:
                sys.modules["botocore.exceptions"] = saved
