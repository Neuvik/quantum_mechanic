"""Tests for the auth code + PKCE flow in providers/entra/exchange.py."""
import base64
import hashlib
import re
from unittest.mock import MagicMock, patch

from quantum_mechanic.providers.entra.exchange import (
    _pkce_pair,
    interactive_authorize,
)


def test_pkce_pair_verifier_format():
    """OUTCOME: verifier is URL-safe base64, 43-128 chars (RFC 7636 §4.1)."""
    verifier, challenge = _pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert re.match(r"^[A-Za-z0-9_-]+$", verifier)


def test_pkce_pair_challenge_is_sha256_of_verifier():
    """OUTCOME: challenge = base64url(SHA256(verifier)) without padding."""
    verifier, challenge = _pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert challenge == expected


def test_pkce_pair_is_random_per_call():
    """OUTCOME: two calls produce different pairs (no static seed)."""
    v1, c1 = _pkce_pair()
    v2, c2 = _pkce_pair()
    assert v1 != v2
    assert c1 != c2


def test_interactive_authorize_returns_token_on_successful_exchange():
    """OUTCOME: with a successful code → token exchange, returns the token dict.

    ANTI-GAMIFICATION: the test injects fake opener + server_factory but the
    PKCE generation, URL building, and token POST are exercised for real
    (httpx mocked).
    """
    fake_server = MagicMock()
    fake_server.captured_code = "fake-auth-code"
    fake_server.captured_state = "fake-state"
    fake_server.captured_error = None
    fake_server.expected_state = "fake-state"
    fake_server.port = 54321
    # handle_request not present → skips the wait loop
    if hasattr(fake_server, "handle_request"):
        del fake_server.handle_request

    opened_urls: list[str] = []
    def fake_opener(url: str) -> bool:
        opened_urls.append(url)
        # Simulate state being captured AFTER opener runs (real browser behavior)
        fake_server.captured_state = fake_server.expected_state
        return True

    fake_token_response = {
        "access_token": "eyJ.fake",
        "refresh_token": "0.AYJ.refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
    }
    mock_resp = MagicMock(status_code=200, json=lambda: fake_token_response)

    with patch("quantum_mechanic.providers.entra.exchange.httpx.Client") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.return_value.__enter__.return_value = mock_client
        mock_client.post.return_value = mock_resp

        result = interactive_authorize(
            tenant_id="t-1",
            client_id="c-1",
            resource="https://graph.microsoft.com",
            opener=fake_opener,
            server_factory=lambda port: fake_server,
        )

    assert result == fake_token_response
    # Authorization URL was opened with PKCE challenge and the captured state
    assert len(opened_urls) == 1
    assert "code_challenge=" in opened_urls[0]
    assert "code_challenge_method=S256" in opened_urls[0]
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A54321" in opened_urls[0]
    assert "callback" not in opened_urls[0]
    # Token POST happened with the captured code
    post_kwargs = mock_client.post.call_args.kwargs
    post_data = post_kwargs.get("data")
    assert post_data is not None
    assert post_data["code"] == "fake-auth-code"
    assert post_data["grant_type"] == "authorization_code"
    assert "code_verifier" in post_data


def test_interactive_authorize_state_mismatch_returns_error():
    """OUTCOME: if callback state doesn't match what we sent, return an error
    dict (defends against CSRF on the redirect).
    """
    fake_server = MagicMock()
    fake_server.captured_code = "fake-code"
    fake_server.captured_state = "TAMPERED-state"
    fake_server.captured_error = None
    fake_server.expected_state = "original-state"
    fake_server.port = 54321
    if hasattr(fake_server, "handle_request"):
        del fake_server.handle_request

    with patch("quantum_mechanic.providers.entra.exchange.httpx.Client"):
        result = interactive_authorize(
            tenant_id="t-1",
            client_id="c-1",
            resource="https://graph.microsoft.com",
            opener=lambda url: None,
            server_factory=lambda port: fake_server,
        )

    assert "error" in result


def test_interactive_authorize_no_code_returns_error():
    """OUTCOME: if the callback never receives a code, return an
    expired/timeout error dict (operator never approved in browser)."""
    fake_server = MagicMock()
    fake_server.captured_code = None  # never set
    fake_server.captured_state = None
    fake_server.captured_error = None
    fake_server.expected_state = "x"
    fake_server.port = 54321
    if hasattr(fake_server, "handle_request"):
        del fake_server.handle_request

    with patch("quantum_mechanic.providers.entra.exchange.httpx.Client"):
        result = interactive_authorize(
            tenant_id="t-1",
            client_id="c-1",
            resource="https://graph.microsoft.com",
            opener=lambda url: None,
            server_factory=lambda port: fake_server,
        )

    assert "error" in result
