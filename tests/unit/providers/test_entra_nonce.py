# ================================================================
# TEST: quantum_mechanic.providers.entra.nonce
# ================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.providers.entra.nonce import (
    _b64url,
    _decode_session_key,
    _sign_jwt,
    fetch_nonce,
    mint_prt_cookie,
)


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _random_session_key() -> bytes:
    return os.urandom(32)


def _key_b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def _key_b64url(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode()


def _decode_jwt_parts(jwt: str) -> tuple[dict, dict, bytes]:
    parts = jwt.split(".")
    assert len(parts) == 3

    def _pad(s: str) -> str:
        return s + "=" * ((4 - len(s) % 4) % 4)

    header = json.loads(base64.urlsafe_b64decode(_pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(_pad(parts[1])))
    sig = base64.urlsafe_b64decode(_pad(parts[2]))
    return header, payload, sig


# ----------------------------------------------------------------
# _decode_session_key
# ----------------------------------------------------------------

class TestDecodeSessionKey:
    def test_standard_base64(self):
        key = os.urandom(32)
        b64 = base64.b64encode(key).decode()
        assert _decode_session_key(b64) == key

    def test_urlsafe_base64_no_padding(self):
        key = os.urandom(32)
        b64url = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
        assert _decode_session_key(b64url) == key

    def test_urlsafe_with_padding(self):
        key = os.urandom(32)
        b64url = base64.urlsafe_b64encode(key).decode()
        assert _decode_session_key(b64url) == key

    def test_strips_whitespace(self):
        key = os.urandom(32)
        b64 = "  " + base64.b64encode(key).decode() + "\n"
        assert _decode_session_key(b64) == key

    def test_dashes_converted(self):
        # URL-safe uses - and _ instead of + and /
        key = os.urandom(32)
        b64url = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
        # Manually put dashes back (they were already there for URL-safe)
        assert _decode_session_key(b64url) == key


# ----------------------------------------------------------------
# _sign_jwt
# ----------------------------------------------------------------

class TestSignJwt:
    def test_produces_three_part_jwt(self):
        key = _random_session_key()
        jwt = _sign_jwt({"alg": "HS256"}, {"sub": "test"}, key)
        assert jwt.count(".") == 2

    def test_signature_verifies(self):
        key = _random_session_key()
        jwt = _sign_jwt({"alg": "HS256", "ctx": "abc"}, {"sub": "test"}, key)
        parts = jwt.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
        assert parts[2] == expected_b64

    def test_header_and_payload_roundtrip(self):
        key = _random_session_key()
        header = {"alg": "HS256", "ctx": "xyz"}
        payload = {"refresh_token": "prt-val", "nonce": "abc123"}
        jwt = _sign_jwt(header, payload, key)
        h, p, _ = _decode_jwt_parts(jwt)
        assert h == header
        assert p == payload

    def test_different_keys_produce_different_sigs(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        jwt1 = _sign_jwt({"alg": "HS256"}, {"sub": "x"}, key1)
        jwt2 = _sign_jwt({"alg": "HS256"}, {"sub": "x"}, key2)
        assert jwt1.split(".")[2] != jwt2.split(".")[2]


# ----------------------------------------------------------------
# mint_prt_cookie
# ----------------------------------------------------------------

class TestMintPrtCookie:
    def test_produces_valid_jwt(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt-value", _key_b64(key), "nonce-abc")
        assert jwt.count(".") == 2

    def test_payload_contains_prt_value(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("my-prt-value", _key_b64(key), "nonce-xyz")
        _, payload, _ = _decode_jwt_parts(jwt)
        assert payload["refresh_token"] == "my-prt-value"

    def test_payload_contains_nonce(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt", _key_b64(key), "my-nonce")
        _, payload, _ = _decode_jwt_parts(jwt)
        assert payload["request_nonce"] == "my-nonce"

    def test_payload_is_primary_true(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt", _key_b64(key), "nonce")
        _, payload, _ = _decode_jwt_parts(jwt)
        assert payload["is_primary"] == "true"

    def test_header_alg_hs256(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt", _key_b64(key), "nonce")
        header, _, _ = _decode_jwt_parts(jwt)
        assert header["alg"] == "HS256"

    def test_header_ctx_present_and_random(self):
        key = _random_session_key()
        jwt1 = mint_prt_cookie("prt", _key_b64(key), "nonce")
        jwt2 = mint_prt_cookie("prt", _key_b64(key), "nonce")
        h1, _, _ = _decode_jwt_parts(jwt1)
        h2, _, _ = _decode_jwt_parts(jwt2)
        assert "ctx" in h1
        # ctx is random — two calls should differ
        assert h1["ctx"] != h2["ctx"]

    def test_accepts_urlsafe_key(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt", _key_b64url(key), "nonce")
        _, payload, _ = _decode_jwt_parts(jwt)
        assert payload["refresh_token"] == "prt"

    def test_signature_verifies_with_session_key(self):
        key = _random_session_key()
        jwt = mint_prt_cookie("prt", _key_b64(key), "nonce")
        parts = jwt.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = hmac.new(key, signing_input, hashlib.sha256).digest()
        actual = base64.urlsafe_b64decode(parts[2] + "==")
        assert actual == expected

    def test_different_nonces_produce_different_cookies(self):
        key = _random_session_key()
        jwt1 = mint_prt_cookie("prt", _key_b64(key), "nonce-1")
        jwt2 = mint_prt_cookie("prt", _key_b64(key), "nonce-2")
        assert jwt1 != jwt2


# ----------------------------------------------------------------
# fetch_nonce
# ----------------------------------------------------------------

class TestFetchNonce:
    def _mock_http(self, json_response: dict) -> MagicMock:
        resp = MagicMock()
        resp.json.return_value = json_response
        client = MagicMock()
        client.post.return_value = resp
        return client

    def test_returns_nonce_from_nonce_field(self):
        client = self._mock_http({"Nonce": "base64nonce=="})
        nonce = fetch_nonce(tenant_id="t", http=client)
        assert nonce == "base64nonce=="

    def test_returns_nonce_from_lowercase_field(self):
        client = self._mock_http({"nonce": "lowercase-nonce"})
        nonce = fetch_nonce(tenant_id="t", http=client)
        assert nonce == "lowercase-nonce"

    def test_extracts_nonce_from_error_description(self):
        client = self._mock_http({
            "error": "invalid_request",
            "error_description": "AADSTS70011: ... Nonce=abc123xyz&other=val",
        })
        nonce = fetch_nonce(tenant_id="t", http=client)
        assert nonce == "abc123xyz"

    def test_raises_when_no_nonce(self):
        client = self._mock_http({"error": "invalid_request", "error_description": "no nonce here"})
        with pytest.raises(ValueError, match="No nonce"):
            fetch_nonce(tenant_id="t", http=client)

    def test_raises_on_http_error(self):
        import httpx
        client = MagicMock()
        client.post.side_effect = httpx.HTTPError("connection refused")
        with pytest.raises(ValueError, match="Failed to fetch nonce"):
            fetch_nonce(tenant_id="t", http=client)

    def test_posts_to_correct_tenant(self):
        client = self._mock_http({"Nonce": "n"})
        fetch_nonce(tenant_id="my-tenant", http=client)
        url = client.post.call_args[0][0]
        assert "my-tenant" in url
