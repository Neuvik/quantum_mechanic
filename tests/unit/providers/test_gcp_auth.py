# ================================================================
# TESTS: GCP Auth Provider
# ================================================================

import json
from unittest.mock import MagicMock, mock_open, patch

import pytest

from quantum_mechanic.providers.gcp.auth import GCPAuthProvider


@pytest.fixture
def provider() -> GCPAuthProvider:
    return GCPAuthProvider()


class TestGCPAuthenticate:
    def test_authenticate_captured_token(self, provider: GCPAuthProvider) -> None:
        """Test authentication with captured_token method."""
        creds = provider.authenticate({
            "method": "captured_token",
            "access_token": "ya29.fake-token",
            "captured_principal": "alice@example.iam.gserviceaccount.com",
            "project_id": "my-project",
        })
        # TokenCredentials stores the bearer token on .token
        assert getattr(creds, "token", None) == "ya29.fake-token"
        assert creds.valid

    def test_authenticate_captured_token_missing_access_token(
        self, provider: GCPAuthProvider
    ) -> None:
        """captured_token requires access_token."""
        with pytest.raises(ValueError, match="captured_token method requires"):
            provider.authenticate({"method": "captured_token"})

    @patch("quantum_mechanic.providers.gcp.auth.Path.exists")
    @patch("quantum_mechanic.providers.gcp.auth.service_account.Credentials.from_service_account_file")
    def test_authenticate_sa_file_success(
        self, mock_from_file: MagicMock, mock_exists: MagicMock, provider: GCPAuthProvider
    ) -> None:
        """Test SA file credential loading."""
        mock_exists.return_value = True
        mock_creds = MagicMock()
        mock_from_file.return_value = mock_creds
        
        creds = provider.authenticate({
            "method": "service_account_file",
            "key_file": "/tmp/key.json"
        })
        assert creds is mock_creds
        mock_from_file.assert_called_once_with(
            "/tmp/key.json", scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

    def test_authenticate_sa_file_missing_key_file(self, provider: GCPAuthProvider) -> None:
        """Test SA file without key_file raises ValueError."""
        with pytest.raises(ValueError, match="requires 'key_file'"):
            provider.authenticate({"method": "service_account_file"})

    @patch("quantum_mechanic.providers.gcp.auth.Path.exists")
    def test_authenticate_sa_file_not_found(self, mock_exists: MagicMock, provider: GCPAuthProvider) -> None:
        """Test SA file when file doesnt exist raises ValueError."""
        mock_exists.return_value = False
        with pytest.raises(ValueError, match="key file not found"):
            provider.authenticate({
                "method": "service_account_file",
                "key_file": "/tmp/key.json"
            })

    @patch("quantum_mechanic.providers.gcp.auth.service_account.Credentials.from_service_account_info")
    def test_authenticate_sa_info_dict(self, mock_from_info: MagicMock, provider: GCPAuthProvider) -> None:
        """Test SA info loading from dict."""
        mock_creds = MagicMock()
        mock_from_info.return_value = mock_creds
        sa_info = {"type": "service_account"}
        
        creds = provider.authenticate({
            "method": "service_account_info",
            "service_account_info": sa_info
        })
        assert creds is mock_creds
        mock_from_info.assert_called_once_with(
            sa_info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

    @patch("quantum_mechanic.providers.gcp.auth.service_account.Credentials.from_service_account_info")
    def test_authenticate_sa_info_str(self, mock_from_info: MagicMock, provider: GCPAuthProvider) -> None:
        """Test SA info loading from JSON string."""
        mock_creds = MagicMock()
        mock_from_info.return_value = mock_creds
        sa_info = {"type": "service_account"}
        
        creds = provider.authenticate({
            "method": "service_account_info",
            "service_account_info": json.dumps(sa_info)
        })
        assert creds is mock_creds
        mock_from_info.assert_called_once_with(
            sa_info, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )

    def test_authenticate_sa_info_missing(self, provider: GCPAuthProvider) -> None:
        """Test SA info without service_account_info raises ValueError."""
        with pytest.raises(ValueError, match="requires 'service_account_info'"):
            provider.authenticate({"method": "service_account_info"})

    def test_authenticate_unknown_method(self, provider: GCPAuthProvider) -> None:
        """Test unknown method raises ValueError."""
        with pytest.raises(ValueError, match="Unknown GCP auth method"):
            provider.authenticate({"method": "invalid"})


# ================================================================
# CANARY: GCP Credential Isolation
# ----------------------------------------------------------------
# Mirror of the Azure canary. This is the regression alarm for the
# silent identity-substitution bug in GCP. It MUST fail until the
# real fix lands.
# ================================================================


def test_imported_gcp_credential_not_substituted_by_local_adc():
    """CANARY: GCP credential imported for SA-A must not be replaced by local ADC SA-B."""
    secret_data = {
        "method": "captured_token",
        "access_token": "ya29.fake-token-for-alice",
        "captured_principal": "alice@example.iam.gserviceaccount.com",
    }

    # local google.auth.default would return a different identity
    impostor_cred = MagicMock()
    impostor_cred.service_account_email = "impostor@example.iam.gserviceaccount.com"
    with patch("google.auth.default", return_value=(impostor_cred, "impostor-project")):
        provider = GCPAuthProvider()
        cred = provider.authenticate(secret_data)
        # The returned credential must carry the alice token, not impostor's identity
        assert getattr(cred, "token", None) == "ya29.fake-token-for-alice"


def test_gcp_method_default_in_stored_secret_raises():
    """OUTCOME: stored {'method': 'default'} raises — same refusal as Azure."""
    provider = GCPAuthProvider()
    with pytest.raises(ValueError, match="references local"):
        provider.authenticate({"method": "default"})


def test_gcp_unknown_method_raises():
    """OUTCOME: An unknown method raises, never silently calls google.auth.default."""
    provider = GCPAuthProvider()
    with pytest.raises(ValueError):
        provider.authenticate({"method": "wat"})


class TestGCPWhoAmI:
    @patch("quantum_mechanic.providers.gcp.auth.google.auth.transport.requests.Request")
    def test_whoami_service_account(self, mock_request: MagicMock, provider: GCPAuthProvider) -> None:
        """Test whoami with service account credentials."""
        mock_creds = MagicMock()
        mock_creds.service_account_email = "test-sa@my-project.iam.gserviceaccount.com"
        mock_creds.project_id = "my-project"
        mock_creds.scopes = ["scope1"]
        
        result = provider.whoami(mock_creds)
        
        mock_creds.refresh.assert_called_once()
        assert result.provider == "gcp"
        assert result.principal_id == "test-sa@my-project.iam.gserviceaccount.com"
        assert result.principal_type == "service_account"
        assert result.friendly_name == "test-sa"
        assert result.account_id == "my-project"
        assert result.extra["scopes"] == ["scope1"]

    @patch("quantum_mechanic.providers.gcp.auth.google.auth.transport.requests.Request")
    @patch("urllib.request.urlopen")
    def test_whoami_user_credential(self, mock_urlopen: MagicMock, mock_request: MagicMock, provider: GCPAuthProvider) -> None:
        """Test whoami with user credentials via tokeninfo."""
        mock_creds = MagicMock()
        # Delete service_account_email attribute so it uses the user flow
        del mock_creds.service_account_email
        mock_creds.project_id = None
        mock_creds.token = "fake-token"
        
        # Mock tokeninfo response
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "email": "user@example.com",
            "email_verified": "true",
            "azp": "my-client-id",
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        result = provider.whoami(mock_creds)
        
        assert result.principal_id == "user@example.com"
        assert result.principal_type == "user"
        assert result.friendly_name == "user"
        assert result.account_id == "my-client-id"

    @patch("quantum_mechanic.providers.gcp.auth.google.auth.transport.requests.Request")
    @patch("urllib.request.urlopen")
    def test_whoami_user_credential_unverified(self, mock_urlopen: MagicMock, mock_request: MagicMock, provider: GCPAuthProvider) -> None:
        """Test whoami with an unverified user email."""
        mock_creds = MagicMock()
        del mock_creds.service_account_email
        mock_creds.project_id = None
        mock_creds.token = "fake-token"
        
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "email": "hacker@example.com",
            "email_verified": "false",
            "aud": "audience-id"
        }).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        
        result = provider.whoami(mock_creds)
        
        assert result.principal_id == "hacker@example.com"
        assert result.principal_type == "unverified_user"
        assert result.account_id == "audience-id"

    @patch("quantum_mechanic.providers.gcp.auth.google.auth.transport.requests.Request")
    def test_whoami_user_no_token(self, mock_request: MagicMock, provider: GCPAuthProvider) -> None:
        """Test whoami gracefully handles missing token."""
        mock_creds = MagicMock()
        del mock_creds.service_account_email
        mock_creds.token = None  # No token
        
        result = provider.whoami(mock_creds)
        
        assert result.principal_id == "unknown"
        assert result.principal_type == "unknown"

    @patch("quantum_mechanic.providers.gcp.auth.google.auth.transport.requests.Request")
    @patch("urllib.request.urlopen")
    def test_whoami_user_api_error(self, mock_urlopen: MagicMock, mock_request: MagicMock, provider: GCPAuthProvider) -> None:
        """Test whoami gracefully handles tokeninfo API errors."""
        mock_creds = MagicMock()
        del mock_creds.service_account_email
        mock_creds.project_id = None
        mock_creds.token = "fake-token"
        
        mock_urlopen.side_effect = Exception("API connection failed")
        
        result = provider.whoami(mock_creds)
        
        assert result.principal_id == "unknown"
        assert result.principal_type == "unknown"
        assert result.account_id == "unknown"
