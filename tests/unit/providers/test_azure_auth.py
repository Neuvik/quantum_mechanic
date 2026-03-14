# ================================================================
# TESTS: Azure Auth Provider
# ================================================================

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from azure.identity import ClientSecretCredential, DefaultAzureCredential

from quantum_mechanic.providers.azure.auth import AzureAuthProvider


@pytest.fixture
def provider() -> AzureAuthProvider:
    return AzureAuthProvider()


class TestAzureAuthenticate:
    def test_authenticate_default(self, provider: AzureAuthProvider) -> None:
        """Test authentication with default method."""
        cred = provider.authenticate({"method": "default"})
        assert isinstance(cred, DefaultAzureCredential)

    def test_authenticate_cli(self, provider: AzureAuthProvider) -> None:
        """Test authentication with cli method."""
        cred = provider.authenticate({"method": "cli"})
        assert isinstance(cred, DefaultAzureCredential)

    def test_authenticate_service_principal_success(self, provider: AzureAuthProvider) -> None:
        """Test SP authentication with all required fields."""
        data = {
            "method": "sp",
            "tenant_id": "t-123",
            "client_id": "c-456",
            "client_secret": "s-789",
        }
        cred = provider.authenticate(data)
        assert isinstance(cred, ClientSecretCredential)

    def test_authenticate_service_principal_missing_tenant(self, provider: AzureAuthProvider) -> None:
        """Test SP authentication missing tenant_id raises ValueError."""
        data = {
            "method": "sp",
            "client_id": "c-456",
            "client_secret": "s-789",
        }
        with pytest.raises(ValueError, match="requires 'tenant_id'"):
            provider.authenticate(data)

    def test_authenticate_fallback(self, provider: AzureAuthProvider) -> None:
        """Test authentication without method falls back to default."""
        cred = provider.authenticate({})
        assert isinstance(cred, DefaultAzureCredential)


class TestAzureWhoAmI:
    def _create_mock_token(self, claims: dict) -> MagicMock:
        """Helper to create a mock Azure token with encoded JWT claims."""
        payload_json = json.dumps(claims)
        # base64url encode without padding
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        
        mock_token = MagicMock()
        mock_token.token = f"HEADER.{payload_b64}.SIGNATURE"
        return mock_token

    @patch("quantum_mechanic.providers.azure.auth.SubscriptionClient")
    def test_whoami_user(self, mock_sub_client_class: MagicMock, provider: AzureAuthProvider) -> None:
        """Test whoami parsing a user token."""
        mock_cred = MagicMock()
        mock_token = self._create_mock_token({
            "oid": "user-oid",
            "tid": "tenant-id",
            "upn": "test@example.com",
            "name": "Test User"
        })
        mock_cred.get_token.return_value = mock_token

        # Mock subscriptions
        mock_sub = MagicMock()
        mock_sub.subscription_id = "sub-123"
        mock_sub.display_name = "Test Sub"
        mock_sub.state = MagicMock(value="Enabled")
        
        mock_sub_client = MagicMock()
        mock_sub_client.subscriptions.list.return_value = [mock_sub]
        mock_sub_client_class.return_value = mock_sub_client

        result = provider.whoami(mock_cred)

        assert result.provider == "azure"
        assert result.principal_id == "user-oid"
        assert result.principal_type == "user"
        assert result.friendly_name == "test@example.com"
        assert result.tenant_id == "tenant-id"
        assert result.account_id == "sub-123"
        assert result.account_name == "Test Sub"
        assert len(result.extra["subscriptions"]) == 1

    @patch("quantum_mechanic.providers.azure.auth.SubscriptionClient")
    def test_whoami_service_principal(self, mock_sub_client_class: MagicMock, provider: AzureAuthProvider) -> None:
        """Test whoami parsing a service principal token."""
        mock_cred = MagicMock()
        mock_token = self._create_mock_token({
            "oid": "sp-oid",
            "tid": "tenant-id",
            "appid": "app-123",
            "app_displayname": "My App"
        })
        mock_cred.get_token.return_value = mock_token
        
        mock_sub_client = MagicMock()
        mock_sub_client.subscriptions.list.return_value = []
        mock_sub_client_class.return_value = mock_sub_client

        result = provider.whoami(mock_cred)

        assert result.principal_type == "service_principal"
        assert result.friendly_name == "My App"
        # Since no subscriptions, account_id falls back to tenant_id
        assert result.account_id == "tenant-id"
        assert result.account_name is None
        assert len(result.extra["subscriptions"]) == 0

    @patch("quantum_mechanic.providers.azure.auth.SubscriptionClient")
    def test_whoami_subscription_error(self, mock_sub_client_class: MagicMock, provider: AzureAuthProvider) -> None:
        """Test whoami when listing subscriptions fails (e.g., restricted access)."""
        mock_cred = MagicMock()
        mock_token = self._create_mock_token({
            "oid": "user-oid",
            "tid": "tenant-id",
            "sub": "subject-123" # Unknown type fallback
        })
        mock_cred.get_token.return_value = mock_token
        
        mock_sub_client_class.side_effect = Exception("API Error")

        result = provider.whoami(mock_cred)

        assert result.principal_type == "unknown"
        assert result.friendly_name == "subject-123"
        assert result.account_id == "tenant-id"
        assert len(result.extra["subscriptions"]) == 0

    def test_whoami_invalid_token(self, provider: AzureAuthProvider) -> None:
        """Test whoami parsing when token is malformed."""
        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = "NOT_A_JWT"
        mock_cred.get_token.return_value = mock_token

        result = provider.whoami(mock_cred)
        assert result.principal_id == "unknown"
        assert result.tenant_id == "unknown"
        assert result.principal_type == "unknown"
