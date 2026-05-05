# ================================================================
# TEST: quantum_mechanic.providers.entra.exchange
# ================================================================

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.entra.exchange import (
    ESTS_BASE,
    exchange_ests_cookie,
    exchange_prt_cookie,
    exchange_refresh_token,
    exchange_ropc,
    initiate_device_code,
    poll_device_code,
)


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _mock_client(json_response: dict, status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Client that returns json_response on POST."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_response

    client = MagicMock()
    client.post.return_value = resp
    client.__enter__ = lambda s: s
    client.__exit__ = MagicMock(return_value=False)
    return client


def _http_error_client() -> MagicMock:
    import httpx
    client = MagicMock()
    client.post.side_effect = httpx.HTTPError("connection refused")
    return client


# ----------------------------------------------------------------
# exchange_prt_cookie
# ----------------------------------------------------------------

class TestExchangePrtCookie:
    def test_success_returns_token_dict(self):
        expected = {"access_token": "eyJ.at", "refresh_token": "0.rt", "token_type": "Bearer"}
        client = _mock_client(expected)
        result = exchange_prt_cookie(
            "prt-jwt",
            tenant_id="tenant-1",
            client_id="client-1",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["access_token"] == "eyJ.at"
        assert result["refresh_token"] == "0.rt"

    def test_posts_to_v1_endpoint(self):
        client = _mock_client({"access_token": "t"})
        exchange_prt_cookie(
            "prt-jwt",
            tenant_id="my-tenant",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        url = client.post.call_args[0][0]
        assert "my-tenant" in url
        assert "oauth2/token" in url  # v1 endpoint

    def test_uses_jwt_bearer_grant(self):
        client = _mock_client({"access_token": "t"})
        exchange_prt_cookie(
            "prt-jwt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        data = client.post.call_args[1]["data"]
        assert data["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert data["assertion"] == "prt-jwt"

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = exchange_prt_cookie(
            "prt-jwt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"
        assert "error_description" in result

    def test_error_response_passthrough(self):
        err = {"error": "invalid_grant", "error_description": "PRT expired"}
        client = _mock_client(err)
        result = exchange_prt_cookie(
            "bad-prt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "invalid_grant"


# ----------------------------------------------------------------
# exchange_ests_cookie
# ----------------------------------------------------------------

class TestExchangeEstsCookie:
    def test_success(self):
        expected = {"access_token": "eyJ.at", "refresh_token": "0.rt"}
        client = _mock_client(expected)
        result = exchange_ests_cookie(
            "opaque-ests",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["access_token"] == "eyJ.at"

    def test_cookie_sent_in_header(self):
        client = _mock_client({"access_token": "t"})
        exchange_ests_cookie(
            "my-ests-value",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            cookie_name="ESTSAUTHPERSISTENT",
            http=client,
        )
        headers = client.post.call_args[1]["headers"]
        assert "ESTSAUTHPERSISTENT=my-ests-value" in headers["Cookie"]

    def test_user_agent_set(self):
        client = _mock_client({"access_token": "t"})
        exchange_ests_cookie(
            "v",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        headers = client.post.call_args[1]["headers"]
        assert "User-Agent" in headers
        assert "Mozilla" in headers["User-Agent"]

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = exchange_ests_cookie(
            "v",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"


# ----------------------------------------------------------------
# initiate_device_code
# ----------------------------------------------------------------

class TestInitiateDeviceCode:
    def test_returns_device_code_response(self):
        expected = {
            "device_code": "BAAQ...",
            "user_code": "ABCD-1234",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
        }
        client = _mock_client(expected)
        result = initiate_device_code(
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["user_code"] == "ABCD-1234"
        assert result["device_code"] == "BAAQ..."

    def test_posts_to_devicecode_endpoint(self):
        client = _mock_client({"device_code": "d"})
        initiate_device_code(
            tenant_id="my-tenant",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        url = client.post.call_args[0][0]
        assert "my-tenant" in url
        assert "devicecode" in url

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = initiate_device_code(
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"


# ----------------------------------------------------------------
# poll_device_code
# ----------------------------------------------------------------

class TestPollDeviceCode:
    def test_success_on_first_poll(self):
        expected = {"access_token": "eyJ.at", "refresh_token": "0.rt"}
        client = _mock_client(expected)
        result = poll_device_code(
            "dev-code",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["access_token"] == "eyJ.at"

    def test_polls_until_success(self):
        resp_pending = MagicMock()
        resp_pending.json.return_value = {"error": "authorization_pending"}
        resp_success = MagicMock()
        resp_success.json.return_value = {"access_token": "eyJ.at"}

        client = MagicMock()
        client.post.side_effect = [resp_pending, resp_pending, resp_success]

        with patch("quantum_mechanic.providers.entra.exchange.time.sleep"):
            result = poll_device_code(
                "dev-code",
                tenant_id="t",
                client_id="c",
                resource="https://graph.microsoft.com",
                interval=1,
                http=client,
            )
        assert result["access_token"] == "eyJ.at"
        assert client.post.call_count == 3

    def test_slow_down_increases_interval(self):
        resp_slow = MagicMock()
        resp_slow.json.return_value = {"error": "slow_down"}
        resp_success = MagicMock()
        resp_success.json.return_value = {"access_token": "eyJ.at"}

        client = MagicMock()
        client.post.side_effect = [resp_slow, resp_success]

        sleep_calls = []
        with patch("quantum_mechanic.providers.entra.exchange.time.sleep", side_effect=lambda s: sleep_calls.append(s)):
            poll_device_code(
                "dev-code",
                tenant_id="t",
                client_id="c",
                resource="https://graph.microsoft.com",
                interval=5,
                http=client,
            )
        # After slow_down, interval becomes 10
        assert sleep_calls[0] == 10

    def test_timeout_returns_expired_token_error(self):
        resp_pending = MagicMock()
        resp_pending.json.return_value = {"error": "authorization_pending"}

        client = MagicMock()
        client.post.return_value = resp_pending

        with patch("quantum_mechanic.providers.entra.exchange.time.sleep"):
            with patch("quantum_mechanic.providers.entra.exchange.time.time", side_effect=[0, 0, 999]):
                result = poll_device_code(
                    "dev-code",
                    tenant_id="t",
                    client_id="c",
                    resource="https://graph.microsoft.com",
                    interval=1,
                    timeout=1,
                    http=client,
                )
        assert result["error"] == "expired_token"

    def test_terminal_error_returned_immediately(self):
        resp = MagicMock()
        resp.json.return_value = {"error": "access_denied", "error_description": "User declined"}
        client = MagicMock()
        client.post.return_value = resp

        result = poll_device_code(
            "dev-code",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "access_denied"
        assert client.post.call_count == 1

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = poll_device_code(
            "dev-code",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"


# ----------------------------------------------------------------
# exchange_refresh_token
# ----------------------------------------------------------------

class TestExchangeRefreshToken:
    def test_success(self):
        expected = {"access_token": "eyJ.at", "refresh_token": "0.new-rt"}
        client = _mock_client(expected)
        result = exchange_refresh_token(
            "0.old-rt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["access_token"] == "eyJ.at"

    def test_uses_refresh_token_grant(self):
        client = _mock_client({"access_token": "t"})
        exchange_refresh_token(
            "0.rt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        data = client.post.call_args[1]["data"]
        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "0.rt"

    def test_scope_includes_default(self):
        client = _mock_client({"access_token": "t"})
        exchange_refresh_token(
            "0.rt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        data = client.post.call_args[1]["data"]
        assert "/.default" in data["scope"]

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = exchange_refresh_token(
            "0.rt",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"


# ----------------------------------------------------------------
# exchange_ropc
# ----------------------------------------------------------------

class TestExchangeRopc:
    def test_success(self):
        expected = {"access_token": "eyJ.at", "refresh_token": "0.rt"}
        client = _mock_client(expected)
        result = exchange_ropc(
            "user@contoso.com",
            "P@ssw0rd",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["access_token"] == "eyJ.at"

    def test_uses_password_grant(self):
        client = _mock_client({"access_token": "t"})
        exchange_ropc(
            "user@contoso.com",
            "P@ssw0rd",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        data = client.post.call_args[1]["data"]
        assert data["grant_type"] == "password"
        assert data["username"] == "user@contoso.com"
        assert data["password"] == "P@ssw0rd"

    def test_http_error_returns_error_dict(self):
        client = _http_error_client()
        result = exchange_ropc(
            "user",
            "pass",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "http_error"

    def test_mfa_error_passthrough(self):
        err = {"error": "interaction_required", "error_description": "MFA required"}
        client = _mock_client(err)
        result = exchange_ropc(
            "user",
            "pass",
            tenant_id="t",
            client_id="c",
            resource="https://graph.microsoft.com",
            http=client,
        )
        assert result["error"] == "interaction_required"
