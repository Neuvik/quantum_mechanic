# ================================================================
# TESTS: quantum_mechanic.providers.aws.auth
# ----------------------------------------------------------------
# WHAT:   Tests AWS authentication and whoami with mocked boto3.
#         No real AWS credentials needed.
#
# WHY:    The AWS provider is the first provider implementation.
#         If ARN parsing or session creation is broken, no AWS
#         technique will work.
# ================================================================

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.aws.auth import AWSAuthProvider


@pytest.fixture
def aws_provider():
    return AWSAuthProvider()


class TestAWSAuthenticate:
    """Test AWS session creation from credential data."""

    @patch("quantum_mechanic.providers.aws.auth.boto3.Session")
    def test_authenticate_with_profile(self, mock_session_cls, aws_provider):
        """Profile-based auth passes profile_name to boto3.Session."""
        aws_provider.authenticate({"profile_name": "sa_key1"})
        mock_session_cls.assert_called_once_with(
            profile_name="sa_key1",
            region_name="us-east-1",
        )

    @patch("quantum_mechanic.providers.aws.auth.boto3.Session")
    def test_authenticate_with_profile_and_region(self, mock_session_cls, aws_provider):
        """Profile + region auth passes both to boto3.Session."""
        aws_provider.authenticate({"profile_name": "test", "region": "us-west-2"})
        mock_session_cls.assert_called_once_with(
            profile_name="test",
            region_name="us-west-2",
        )

    @patch("quantum_mechanic.providers.aws.auth.boto3.Session")
    def test_authenticate_with_access_key(self, mock_session_cls, aws_provider):
        """Access key auth passes key ID and secret to boto3.Session."""
        aws_provider.authenticate(
            {
                "access_key_id": "AKIAEXAMPLE",
                "secret_access_key": "secretsecret",
            }
        )
        mock_session_cls.assert_called_once_with(
            aws_access_key_id="AKIAEXAMPLE",
            aws_secret_access_key="secretsecret",
            aws_session_token=None,
            region_name="us-east-1",
        )

    @patch("quantum_mechanic.providers.aws.auth.boto3.Session")
    def test_authenticate_with_session_token(self, mock_session_cls, aws_provider):
        """STS session token auth includes all three credential parts."""
        aws_provider.authenticate(
            {
                "access_key_id": "ASIAEXAMPLE",
                "secret_access_key": "secret",
                "session_token": "FwoGZX...",
            }
        )
        mock_session_cls.assert_called_once_with(
            aws_access_key_id="ASIAEXAMPLE",
            aws_secret_access_key="secret",
            aws_session_token="FwoGZX...",
            region_name="us-east-1",
        )

    def test_authenticate_missing_fields_raises(self, aws_provider):
        """Auth with no profile or access_key raises ValueError."""
        with pytest.raises(ValueError, match="access_key_id"):
            aws_provider.authenticate({"region": "us-east-1"})


class TestAWSWhoAmI:
    """Test AWS identity resolution with mocked STS responses."""

    def _mock_session(self, arn, account, user_id):
        """Build a mock boto3.Session with STS get_caller_identity."""
        session = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {
            "Arn": arn,
            "Account": account,
            "UserId": user_id,
        }
        session.client.return_value = sts_client
        return session

    def test_whoami_iam_user(self, aws_provider):
        """IAM user ARN parses to type=user."""
        session = self._mock_session(
            "arn:aws:iam::123456789012:user/svc-deploy",
            "123456789012",
            "AIDAEXAMPLE",
        )
        result = aws_provider.whoami(session)
        assert result.provider == "aws"
        assert result.principal_type == "user"
        assert result.friendly_name == "svc-deploy"
        assert result.account_id == "123456789012"

    def test_whoami_assumed_role(self, aws_provider):
        """Assumed role ARN parses to type=assumed_role."""
        session = self._mock_session(
            "arn:aws:sts::123456789012:assumed-role/AdminRole/session-name",
            "123456789012",
            "AROAEXAMPLE:session-name",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "assumed_role"
        assert result.friendly_name == "AdminRole"

    def test_whoami_root(self, aws_provider):
        """Root ARN parses to type=root."""
        session = self._mock_session(
            "arn:aws:iam::123456789012:root",
            "123456789012",
            "123456789012",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "root"
        assert "root" in result.friendly_name

    def test_whoami_role(self, aws_provider):
        """Role ARN parses to type=role."""
        session = self._mock_session(
            "arn:aws:iam::123456789012:role/BackupAdminRole",
            "123456789012",
            "AROAEXAMPLE",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "role"
        assert result.friendly_name == "BackupAdminRole"

    def test_whoami_federated_user(self, aws_provider):
        """Federated user ARN parses to type=federated_user."""
        session = self._mock_session(
            "arn:aws:sts::123456789012:federated-user/bob",
            "123456789012",
            "123456789012:bob",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "federated_user"
        assert result.friendly_name == "bob"

    def test_whoami_raw_response(self, aws_provider):
        """Raw response is preserved on the result."""
        session = self._mock_session(
            "arn:aws:iam::123456789012:user/test",
            "123456789012",
            "AIDATEST",
        )
        result = aws_provider.whoami(session)
        assert result.raw_response["Arn"] == "arn:aws:iam::123456789012:user/test"

    def test_provider_name(self, aws_provider):
        """Provider name is 'aws'."""
        assert aws_provider.provider_name == "aws"

    def test_whoami_malformed_arn(self, aws_provider):
        """Malformed ARN without 6 parts returns unknown."""
        session = self._mock_session(
            "arn:aws:iam:bad-arn",
            "123",
            "USER",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "unknown"
        assert result.friendly_name == "arn:aws:iam:bad-arn"

    def test_whoami_unknown_type(self, aws_provider):
        """Unknown resource type (e.g. group) returns unknown."""
        session = self._mock_session(
            "arn:aws:iam::123456789012:group/Admins",
            "123456789012",
            "AGPAEXAMPLE",
        )
        result = aws_provider.whoami(session)
        assert result.principal_type == "unknown"
        assert result.friendly_name == "group/Admins"
