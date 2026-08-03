# ================================================================
# TESTS: discovery/enum_s3_buckets
# ================================================================

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, create_autospec, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.techniques.discovery.enum_s3_buckets import (
    _load_wordlist,
    _summarise_acl,
    execute,
)


def _ctx(params: dict | None = None, has_session: bool = False) -> MagicMock:
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.provider_name = "aws"
    ctx.params = params or {}
    ctx.get_param.side_effect = lambda name, default=None: ctx.params.get(name, default)
    ctx.safe_mode = False
    ctx.session = MagicMock() if has_session else None
    ctx.info = MagicMock()
    return ctx


# ================================================================
# Wordlist loading
# ================================================================

class TestLoadWordlist:
    def test_builtin_s3_common_exists(self):
        lines = _load_wordlist("s3-common")
        assert lines is not None
        assert len(lines) > 10

    def test_builtin_s3_permutations_exists(self):
        lines = _load_wordlist("s3-permutations")
        assert lines is not None
        assert len(lines) > 10

    def test_file_path(self, tmp_path):
        wl = tmp_path / "custom.txt"
        wl.write_text("bucket-one\nbucket-two\n")
        lines = _load_wordlist(str(wl))
        assert lines == ["bucket-one", "bucket-two"]

    def test_nonexistent_returns_none(self):
        assert _load_wordlist("does-not-exist-xyz") is None


# ================================================================
# ACL summariser
# ================================================================

class TestSummariseAcl:
    def test_all_users_read(self):
        grants = [{
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "READ",
        }]
        assert _summarise_acl(grants) == "AllUsers: [READ]"

    def test_auth_users_read(self):
        grants = [{
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
            "Permission": "READ",
        }]
        assert _summarise_acl(grants) == "AuthUsers: [READ]"

    def test_multiple_grants(self):
        grants = [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"},
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "WRITE"},
        ]
        result = _summarise_acl(grants)
        assert "AllUsers" in result
        assert "READ" in result
        assert "WRITE" in result

    def test_no_public_grants_returns_empty(self):
        grants = [{"Grantee": {"ID": "abc123"}, "Permission": "FULL_CONTROL"}]
        assert _summarise_acl(grants) == ""

    def test_empty_returns_empty(self):
        assert _summarise_acl([]) == ""


# ================================================================
# execute — sad paths
# ================================================================

class TestExecuteSadPaths:
    def test_missing_wordlist_returns_error(self):
        ctx = _ctx(params={"wordlist": "no-such-list-xyz"})
        result = execute(ctx)
        assert "error" in result
        assert "buckets" in result

    def test_missing_wordlist_param_returns_error(self):
        ctx = _ctx(params={})
        result = execute(ctx)
        assert "error" in result


# ================================================================
# execute — HTTP scan (mocked)
# ================================================================

class TestExecuteScan:
    @patch("quantum_mechanic.techniques.discovery.enum_s3_buckets.requests")
    def test_found_bucket_appears_in_results(self, mock_requests):
        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        hit_resp = MagicMock()
        hit_resp.status_code = 200
        hit_resp.headers = {"x-amz-bucket-region": "us-east-1"}

        miss_resp = MagicMock()
        miss_resp.status_code = 404

        def _head(url, **kwargs):
            if "backup" in url:
                return hit_resp
            return miss_resp

        mock_session.head.side_effect = _head

        ctx = _ctx(params={"wordlist": "s3-common", "threads": "2"})
        result = execute(ctx)

        assert "buckets" in result
        assert result["total_checked"] > 0
        buckets = [b["bucket"] for b in result["buckets"]]
        assert any("backup" in b for b in buckets)

    @patch("quantum_mechanic.techniques.discovery.enum_s3_buckets.requests")
    def test_acl_fetched_when_session_present(self, mock_requests):
        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        hit_resp = MagicMock()
        hit_resp.status_code = 200
        hit_resp.headers = {"x-amz-bucket-region": "us-east-1"}
        mock_session.head.return_value = hit_resp

        ctx = _ctx(params={"wordlist": "s3-common", "threads": "2"}, has_session=True)

        mock_s3 = MagicMock()
        ctx.session.client.return_value = mock_s3
        mock_s3.get_bucket_acl.return_value = {"Grants": [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"},
        ]}

        result = execute(ctx)
        assert ctx.session.client.called
        assert any(b.get("acl") for b in result["buckets"])

    @patch("quantum_mechanic.techniques.discovery.enum_s3_buckets.requests")
    def test_no_session_skips_acl(self, mock_requests):
        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session

        hit_resp = MagicMock()
        hit_resp.status_code = 200
        hit_resp.headers = {"x-amz-bucket-region": "us-east-1"}
        mock_session.head.return_value = hit_resp

        ctx = _ctx(params={"wordlist": "s3-common", "threads": "2"}, has_session=False)
        result = execute(ctx)

        assert "buckets" in result
        for b in result["buckets"]:
            assert b.get("acl") == ""

    @patch("quantum_mechanic.techniques.discovery.enum_s3_buckets.requests")
    def test_domain_permutations_expand_candidates(self, mock_requests):
        mock_session = MagicMock()
        mock_requests.Session.return_value = mock_session
        mock_session.head.return_value = MagicMock(status_code=404)

        ctx = _ctx(params={"wordlist": "s3-common", "domain": "acme", "threads": "2"})
        result = execute(ctx)

        # total_checked should be more than len(wordlist) due to permutations
        lines = _load_wordlist("s3-common")
        base_count = sum(1 for l in lines if l.strip() and not l.startswith("#"))
        assert result["total_checked"] > base_count
