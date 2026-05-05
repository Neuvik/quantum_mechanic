# ================================================================
# TESTS: OCI Auth Provider
# ================================================================

import logging
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.oci.auth import OCIAuthProvider

# Mock OCI exceptions using standard Exception as base for tests
class MockServiceError(Exception):
    def __init__(self, message: str):
        self.message = message


@pytest.fixture
def provider() -> OCIAuthProvider:
    return OCIAuthProvider()


class TestOCIAuthenticate:
    @patch("quantum_mechanic.providers.oci.auth.oci.auth.signers.InstancePrincipalsSecurityTokenSigner")
    def test_authenticate_instance_principal(self, mock_signer_class: MagicMock, provider: OCIAuthProvider) -> None:
        """Test authentication via instance principal."""
        mock_signer = MagicMock()
        mock_signer.region = "us-ashburn-1"
        mock_signer_class.return_value = mock_signer
        
        result = provider.authenticate({"method": "instance_principal"})
        
        assert result["config"] == {"region": "us-ashburn-1"}
        assert result["signer"] is mock_signer

    @patch("quantum_mechanic.providers.oci.auth.oci.config.validate_config")
    @patch("quantum_mechanic.providers.oci.auth.oci.config.from_file")
    def test_authenticate_config_file_default(self, mock_from_file: MagicMock, mock_validate: MagicMock, provider: OCIAuthProvider) -> None:
        """Test authentication via default config file."""
        mock_config = {"user": "user-123"}
        mock_from_file.return_value = mock_config
        
        # OCI sets DEFAULT_LOCATION, we mock the call behavior
        with patch("quantum_mechanic.providers.oci.auth.oci.config.DEFAULT_LOCATION", "~/.oci/config"):
            result = provider.authenticate({"method": "config_file"})
            
        assert result["config"] == mock_config
        assert result["signer"] is None
        mock_from_file.assert_called_once_with(file_location="~/.oci/config", profile_name="DEFAULT")
        mock_validate.assert_called_once_with(mock_config)

    @patch("quantum_mechanic.providers.oci.auth.oci.config.validate_config")
    @patch("quantum_mechanic.providers.oci.auth.oci.config.from_file")
    def test_authenticate_config_file_custom(self, mock_from_file: MagicMock, mock_validate: MagicMock, provider: OCIAuthProvider) -> None:
        """Test authentication via custom config file and profile."""
        mock_config = {"user": "user-123"}
        mock_from_file.return_value = mock_config
        
        result = provider.authenticate({
            "method": "config_file",
            "config_file": "/custom/path",
            "profile": "prod"
        })
            
        assert result["config"] == mock_config
        mock_from_file.assert_called_once_with(file_location="/custom/path", profile_name="prod")

    @patch("quantum_mechanic.providers.oci.auth.oci.config.validate_config")
    def test_authenticate_inline_success(self, mock_validate: MagicMock, provider: OCIAuthProvider) -> None:
        """Test authentication via inline configuration."""
        data = {
            "method": "inline",
            "user": "u1",
            "tenancy": "t1",
            "fingerprint": "f1",
            "key_content": "k1",
            "region": "r1",
            "pass_phrase": "p1"
        }
        
        result = provider.authenticate(data)
        
        assert result["config"]["user"] == "u1"
        assert result["config"]["pass_phrase"] == "p1"
        assert result["signer"] is None
        mock_validate.assert_called_once()

    def test_authenticate_inline_missing_fields(self, provider: OCIAuthProvider) -> None:
        """Test inline auth missing required fields raises ValueError."""
        data = {
            "method": "inline",
            "user": "u1",
            # missing tenancy, fingerprint, etc.
        }
        
        with pytest.raises(ValueError, match="OCI inline config requires"):
            provider.authenticate(data)


class TestOCIWhoAmI:
    @pytest.fixture
    def mock_exceptions(self, monkeypatch: pytest.MonkeyPatch):
        # Mock oci.exceptions.ServiceError so we can catch it
        mock_oci = MagicMock()
        mock_oci.exceptions.ServiceError = MockServiceError
        monkeypatch.setattr("quantum_mechanic.providers.oci.auth.oci", mock_oci)
        return mock_oci

    @patch("quantum_mechanic.providers.oci.auth.oci.identity.IdentityClient")
    def test_whoami_user(self, mock_client_class: MagicMock, provider: OCIAuthProvider) -> None:
        """Test whoami with a normal user configuration."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock get_user response
        user_data = MagicMock()
        user_data.id = "ocid1.user.123"
        user_data.name = "testuser"
        user_data.email = "test@example.com"
        user_data.lifecycle_state = "ACTIVE"
        user_data.is_mfa_activated = True
        user_data.time_created = "2023-01-01T00:00:00.000Z"
        mock_user_resp = MagicMock()
        mock_user_resp.data = user_data
        mock_client.get_user.return_value = mock_user_resp
        
        # Mock get_tenancy response
        tenancy_data = MagicMock()
        tenancy_data.id = "ocid1.tenancy.456"
        tenancy_data.name = "mytenancy"
        tenancy_data.home_region_key = "IAD"
        mock_tenancy_resp = MagicMock()
        mock_tenancy_resp.data = tenancy_data
        mock_client.get_tenancy.return_value = mock_tenancy_resp
        
        session = {
            "config": {
                "user": "ocid1.user.123",
                "tenancy": "ocid1.tenancy.456",
                "region": "us-ashburn-1"
            }
        }
        
        result = provider.whoami(session)
        
        assert result.provider == "oci"
        assert result.principal_id == "ocid1.user.123"
        assert result.principal_type == "user"
        assert result.friendly_name == "testuser"
        assert result.account_id == "ocid1.tenancy.456"
        assert result.account_name == "mytenancy"
        assert result.extra["email"] == "test@example.com"
        assert result.extra["region"] == "us-ashburn-1"
        assert "user" in result.raw_response
        assert "tenancy" in result.raw_response

    @patch("quantum_mechanic.providers.oci.auth.oci.identity.IdentityClient")
    def test_whoami_instance_principal(self, mock_client_class: MagicMock, provider: OCIAuthProvider) -> None:
        """Test whoami with instance principal (no user OCID)."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock get_tenancy response
        tenancy_data = MagicMock()
        tenancy_data.id = "ocid1.tenancy.456"
        tenancy_data.name = "mytenancy"
        mock_tenancy_resp = MagicMock()
        mock_tenancy_resp.data = tenancy_data
        mock_client.get_tenancy.return_value = mock_tenancy_resp
        
        mock_signer = MagicMock()
        
        session = {
            "config": {
                "tenancy": "ocid1.tenancy.456"
            },
            "signer": mock_signer
        }
        
        result = provider.whoami(session)
        
        # get_user should not be called since user OCID is absent
        mock_client.get_user.assert_not_called()
        
        assert result.principal_id == "instance-principal"
        assert result.principal_type == "instance_principal"
        assert result.friendly_name == "instance-principal"
        assert result.account_id == "ocid1.tenancy.456"
        assert result.account_name == "mytenancy"

    @patch("quantum_mechanic.providers.oci.auth.oci.identity.IdentityClient")
    def test_whoami_user_service_error_with_signer(self, mock_client_class: MagicMock, mock_exceptions: MagicMock, provider: OCIAuthProvider, caplog) -> None:
        """Test whoami when get_user fails but we have a signer (falls back to instance principal)."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        mock_client.get_user.side_effect = MockServiceError("Not Authorized")
        mock_client.get_tenancy.side_effect = MockServiceError("Not Authorized")
        
        session = {
            "config": {
                "user": "ocid1.user.123",
                "tenancy": "ocid1.tenancy.456"
            },
            "signer": MagicMock()
        }
        
        with caplog.at_level(logging.WARNING):
            result = provider.whoami(session)
            
        assert "get_user failed: Not Authorized" in caplog.text
        assert "get_tenancy failed: Not Authorized" in caplog.text
        
        assert result.principal_type == "instance_principal"
        assert result.friendly_name == "instance-principal"
        assert result.account_name is None

    @patch("quantum_mechanic.providers.oci.auth.oci.identity.IdentityClient")
    def test_whoami_user_service_error_without_signer(self, mock_client_class: MagicMock, mock_exceptions: MagicMock, provider: OCIAuthProvider, caplog) -> None:
        """Test whoami when get_user fails and there is no signer (returns unknown)."""
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.get_user.side_effect = MockServiceError("Permission Denied")
        
        session = {
            "config": {
                "user": "ocid1.user.123",
                "tenancy": "ocid1.tenancy.456"
            },
            "signer": None
        }
        
        result = provider.whoami(session)
        assert result.principal_type == "user"
        assert result.friendly_name == "unknown-user"
