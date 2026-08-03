# ================================================================
# TESTS: Azure Auth Provider
# ================================================================

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from azure.identity import ClientSecretCredential

from quantum_mechanic.providers.azure.auth import AzureAuthProvider
from quantum_mechanic.providers.azure.static_token import StaticTokenCredential


@pytest.fixture
def provider() -> AzureAuthProvider:
    return AzureAuthProvider()


class TestAzureAuthenticate:
    def test_authenticate_captured_token(self, provider: AzureAuthProvider) -> None:
        """Test authentication with captured_token method."""
        cred = provider.authenticate({
            "method": "captured_token",
            "access_token": "fake-jwt-token",
            "expires_on": 9999999999,
            "captured_principal": "user@example.com",
        })
        assert isinstance(cred, StaticTokenCredential)

    def test_authenticate_captured_token_missing_access_token(
        self, provider: AzureAuthProvider
    ) -> None:
        """Test captured_token requires access_token."""
        with pytest.raises(ValueError, match="captured_token method requires"):
            provider.authenticate({"method": "captured_token", "expires_on": 9999999999})

    def test_authenticate_captured_token_missing_expires_on(
        self, provider: AzureAuthProvider
    ) -> None:
        """Test captured_token requires expires_on."""
        with pytest.raises(ValueError, match="captured_token method requires"):
            provider.authenticate({"method": "captured_token", "access_token": "x"})

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


# ================================================================
# CANARY: Credential Isolation
# ----------------------------------------------------------------
# This test is the regression alarm for the silent identity-
# substitution bug. It MUST fail until the real fix lands.
# ================================================================


def _fake_jwt_for(upn: str, oid: str, tid: str) -> str:
    """Build a fake unsigned JWT with the given claims (header.payload.sig style)."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    claims = {"upn": upn, "oid": oid, "tid": tid}
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_imported_credential_not_substituted_by_local_state():
    """CANARY: credential imported as User-A must not be silently replaced by User-B
    when the local az session is User-B.

    This is the regression alarm for credential isolation. If this test ever fails,
    the harness is unsafe to use against customer engagements.

    The fix removes DefaultAzureCredential from azure.auth entirely. We assert that
    the module has no such symbol AND that authenticate() returns a credential whose
    get_token() returns ONLY the stored bytes (no local-state lookup possible).
    """
    import quantum_mechanic.providers.azure.auth as azure_auth_mod

    # Structural assertion: the silent-substitution path is gone from the module.
    assert not hasattr(azure_auth_mod, "DefaultAzureCredential"), (
        "azure.auth must not import DefaultAzureCredential — that was the substitution "
        "vector. Capture-at-import is the only allowed path for local CLI state."
    )

    # Operator imported credential for alice@target-org.example.
    secret_data = {
        "method": "captured_token",
        "access_token": _fake_jwt_for("alice@target-org.example", "oid-A", "tid-A"),
        "expires_on": 9999999999,  # far future
        "captured_principal": "alice@target-org.example",
    }

    provider = AzureAuthProvider()
    credential = provider.authenticate(secret_data)
    result = provider.whoami(credential)

    assert result.friendly_name == "alice@target-org.example", (
        f"Expected alice@target-org.example, got {result.friendly_name!r} — "
        "credential isolation is broken: stored credential was replaced "
        "by local az session at use time."
    )
    assert result.tenant_id == "tid-A", f"Tenant must match stored cred, got {result.tenant_id!r}"


# ================================================================
# REFUSAL TESTS: Local-state credentials must never be silently used
# ----------------------------------------------------------------
# These guard against re-introduction of the substitution bug class.
# Any stored credential that references local CLI state must raise.
# ================================================================


def test_method_default_in_stored_secret_raises():
    """OUTCOME: A stored credential with method='default' raises — that's the bug shape."""
    provider = AzureAuthProvider()
    with pytest.raises(ValueError, match="references local CLI state"):
        provider.authenticate({"method": "default"})


def test_method_cli_in_stored_secret_raises():
    """OUTCOME: A stored credential with method='cli' raises — same bug class."""
    provider = AzureAuthProvider()
    with pytest.raises(ValueError, match="references local CLI state"):
        provider.authenticate({"method": "cli"})


def test_empty_method_in_stored_secret_raises():
    """OUTCOME: A stored credential with no method also raises — defensive."""
    provider = AzureAuthProvider()
    with pytest.raises(ValueError, match="references local CLI state"):
        provider.authenticate({})


def test_unknown_method_raises_not_silent():
    """OUTCOME: An unknown method raises ValueError, not silent DefaultAzureCredential fallback."""
    provider = AzureAuthProvider()
    with pytest.raises(ValueError, match="Unrecognized Azure credential method"):
        provider.authenticate({"method": "wat"})
