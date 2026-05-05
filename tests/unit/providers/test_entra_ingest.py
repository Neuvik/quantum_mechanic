# ================================================================
# TEST: quantum_mechanic.providers.entra.ingest
# ================================================================

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest

from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS, FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.ingest import (
    _flatten_token_dict,
    _parse_profile,
    ingest_access_token,
    ingest_browserdump,
    ingest_ests_cookie,
    ingest_prt_cookie,
    ingest_prt_key,
    ingest_refresh_token,
    ingest_roadtools,
)
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _make_jwt(payload: dict) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.fakesig"


def _future_exp(minutes: int = 60) -> int:
    return int(time.time()) + minutes * 60


def _past_exp(minutes: int = 10) -> int:
    return int(time.time()) - minutes * 60


# ----------------------------------------------------------------
# ingest_prt_cookie
# ----------------------------------------------------------------

class TestIngestPrtCookie:
    def test_token_type(self):
        jwt = _make_jwt({"tid": "t-1", "exp": _future_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.token_type == "prt_cookie"

    def test_tenant_extracted_from_claims(self):
        jwt = _make_jwt({"tid": "tenant-abc", "exp": _future_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.tenant_id == "tenant-abc"

    def test_expires_at_set_from_exp(self):
        jwt = _make_jwt({"exp": _future_exp(5)})
        tok = ingest_prt_cookie(jwt)
        assert tok.expires_at is not None
        assert not tok.is_expired

    def test_device_claims_always_true(self):
        jwt = _make_jwt({"exp": _future_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.device_claims is True

    def test_expired_prt_cookie(self):
        jwt = _make_jwt({"exp": _past_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.is_expired is True

    def test_raw_claims_stored(self):
        jwt = _make_jwt({"tid": "t", "oid": "user-1", "exp": _future_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.raw_claims.get("oid") == "user-1"

    def test_value_preserved(self):
        jwt = _make_jwt({"exp": _future_exp()})
        tok = ingest_prt_cookie(jwt)
        assert tok.value == jwt


# ----------------------------------------------------------------
# ingest_ests_cookie
# ----------------------------------------------------------------

class TestIngestEstsCookie:
    def test_token_type(self):
        tok = ingest_ests_cookie("opaque-cookie-value")
        assert tok.token_type == "ests_cookie"

    def test_value_preserved(self):
        tok = ingest_ests_cookie("some-value")
        assert tok.value == "some-value"

    def test_tenant_id_optional(self):
        tok = ingest_ests_cookie("v", tenant_id="tenant-x")
        assert tok.tenant_id == "tenant-x"

    def test_no_tenant_none(self):
        tok = ingest_ests_cookie("v")
        assert tok.tenant_id is None

    def test_device_claims_false(self):
        tok = ingest_ests_cookie("v")
        assert tok.device_claims is False

    def test_no_expiry(self):
        tok = ingest_ests_cookie("v")
        assert tok.expires_at is None
        assert tok.is_expired is False


# ----------------------------------------------------------------
# ingest_access_token
# ----------------------------------------------------------------

class TestIngestAccessToken:
    def test_token_type(self):
        jwt = _make_jwt({"aud": GRAPH, "exp": _future_exp(), "tid": "t"})
        tok = ingest_access_token(jwt)
        assert tok.token_type == "access_token"

    def test_resource_default_graph(self):
        jwt = _make_jwt({"aud": GRAPH, "exp": _future_exp()})
        tok = ingest_access_token(jwt)
        assert tok.resource == GRAPH

    def test_resource_override(self):
        from quantum_mechanic.providers.entra.token_store import ARM
        jwt = _make_jwt({"aud": ARM, "exp": _future_exp()})
        tok = ingest_access_token(jwt, resource=ARM)
        assert tok.resource == ARM

    def test_tenant_from_claims(self):
        jwt = _make_jwt({"tid": "my-tenant", "exp": _future_exp()})
        tok = ingest_access_token(jwt)
        assert tok.tenant_id == "my-tenant"


# ----------------------------------------------------------------
# ingest_refresh_token
# ----------------------------------------------------------------

class TestIngestRefreshToken:
    def test_token_type(self):
        tok = ingest_refresh_token("0.fake-rt")
        assert tok.token_type == "refresh_token"

    def test_value_preserved(self):
        tok = ingest_refresh_token("0.fake-rt")
        assert tok.value == "0.fake-rt"

    def test_foci_true_for_known_client(self):
        tok = ingest_refresh_token("rt", client_id=FOCI_DEFAULT_CLIENT)
        assert tok.foci is True

    def test_foci_false_for_unknown_client(self):
        tok = ingest_refresh_token("rt", client_id="not-a-foci-client-id")
        assert tok.foci is False

    def test_foci_false_when_no_client(self):
        tok = ingest_refresh_token("rt")
        assert tok.foci is False

    def test_tenant_id_stored(self):
        tok = ingest_refresh_token("rt", tenant_id="t-99")
        assert tok.tenant_id == "t-99"


# ----------------------------------------------------------------
# ingest_prt_key
# ----------------------------------------------------------------

class TestIngestPrtKey:
    def test_token_type(self):
        tok = ingest_prt_key("raw-prt", "hex-key", tenant_id="t")
        assert tok.token_type == "prt_with_key"

    def test_value_is_prt(self):
        tok = ingest_prt_key("raw-prt", "hex-key", tenant_id="t")
        assert tok.value == "raw-prt"

    def test_session_key_in_raw_claims(self):
        tok = ingest_prt_key("prt-val", "sk-abc123", tenant_id="t")
        assert tok.raw_claims["session_key"] == "sk-abc123"

    def test_tenant_id_in_raw_claims(self):
        tok = ingest_prt_key("prt-val", "sk", tenant_id="tenant-x")
        assert tok.raw_claims["tenant_id"] == "tenant-x"

    def test_device_claims_true(self):
        tok = ingest_prt_key("prt", "key", tenant_id="t")
        assert tok.device_claims is True

    def test_no_expiry_pressure(self):
        tok = ingest_prt_key("prt", "key", tenant_id="t")
        assert tok.expires_at is None


# ----------------------------------------------------------------
# _flatten_token_dict
# ----------------------------------------------------------------

class TestFlattenTokenDict:
    def test_basic_conversion(self):
        d = {"prt_cookie": "eyJ...", "ests": "opaque"}
        result = _flatten_token_dict(d)
        names = {e["name"] for e in result}
        assert names == {"prt_cookie", "ests"}

    def test_empty_values_skipped(self):
        d = {"prt_cookie": "eyJ...", "empty_key": ""}
        result = _flatten_token_dict(d)
        assert len(result) == 1
        assert result[0]["name"] == "prt_cookie"

    def test_non_string_values_skipped(self):
        d = {"good": "value", "bad": {"nested": "dict"}}
        result = _flatten_token_dict(d)
        assert len(result) == 1

    def test_empty_dict(self):
        assert _flatten_token_dict({}) == []


# ----------------------------------------------------------------
# _parse_profile
# ----------------------------------------------------------------

class TestParseProfile:
    def _prt_jwt(self) -> str:
        return _make_jwt({"tid": "t-profile", "exp": _future_exp()})

    def test_returns_none_on_no_tokens(self):
        result = _parse_profile({"tenant": "t", "tokens": []})
        assert result is None

    def test_infers_tenant_from_token_claims(self):
        jwt = _make_jwt({"tid": "inferred-tid", "exp": _future_exp()})
        data = {
            "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt}],
        }
        store = _parse_profile(data)
        assert store is not None
        assert store.tenant_id == "inferred-tid"

    def test_explicit_tenant_takes_precedence(self):
        jwt = _make_jwt({"tid": "from-jwt", "exp": _future_exp()})
        data = {
            "tenant": "from-field",
            "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt}],
        }
        store = _parse_profile(data)
        assert store is not None
        assert store.tenant_id == "from-field"

    def test_prt_cookie_classified_correctly(self):
        jwt = self._prt_jwt()
        data = {"tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt}]}
        store = _parse_profile(data)
        assert store is not None
        types = {t.token_type for t in store.tokens}
        assert "prt_cookie" in types

    def test_ests_cookie_classified_correctly(self):
        data = {
            "tenant": "t",
            "tokens": [{"name": "ESTSAUTHPERSISTENT", "value": "opaque-ests"}],
        }
        store = _parse_profile(data)
        assert store is not None
        types = {t.token_type for t in store.tokens}
        assert "ests_cookie" in types

    def test_unknown_cookie_name_skipped(self):
        data = {
            "tenant": "t",
            "tokens": [{"name": "unknown_cookie", "value": "something"}],
        }
        result = _parse_profile(data)
        assert result is None

    def test_explicit_type_field_overrides_name(self):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "tokens": [{"name": "anything", "type": "prt_cookie", "value": jwt}],
        }
        store = _parse_profile(data)
        assert store is not None
        assert any(t.token_type == "prt_cookie" for t in store.tokens)


# ----------------------------------------------------------------
# ingest_browserdump
# ----------------------------------------------------------------

class TestIngestBrowserdump:
    def _write_dump(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "dump.json"
        p.write_text(json.dumps(data))
        return p

    def test_single_profile_flat(self, tmp_path):
        jwt = _make_jwt({"tid": "flat-tenant", "exp": _future_exp()})
        data = {
            "tenant": "flat-tenant",
            "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt}],
        }
        path = self._write_dump(tmp_path, data)
        stores = ingest_browserdump(path)
        assert len(stores) == 1
        assert stores[0].tenant_id == "flat-tenant"

    def test_multi_profile(self, tmp_path):
        jwt_a = _make_jwt({"tid": "t-a", "exp": _future_exp()})
        jwt_b = _make_jwt({"tid": "t-b", "exp": _future_exp()})
        data = {
            "profiles": [
                {
                    "tenant": "t-a",
                    "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt_a}],
                },
                {
                    "tenant": "t-b",
                    "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt_b}],
                },
            ]
        }
        path = self._write_dump(tmp_path, data)
        stores = ingest_browserdump(path)
        assert len(stores) == 2
        tenant_ids = {s.tenant_id for s in stores}
        assert {"t-a", "t-b"} == tenant_ids

    def test_empty_profiles_filtered(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "profiles": [
                {"tenant": "t", "tokens": [{"name": "x-ms-RefreshTokenCredential", "value": jwt}]},
                {"tenant": "t2", "tokens": []},
            ]
        }
        path = self._write_dump(tmp_path, data)
        stores = ingest_browserdump(path)
        assert len(stores) == 1

    def test_dict_tokens_format(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "tenant": "t",
            "tokens": {"x-ms-RefreshTokenCredential": jwt},
        }
        path = self._write_dump(tmp_path, data)
        stores = ingest_browserdump(path)
        assert len(stores) == 1
        assert any(t.token_type == "prt_cookie" for t in stores[0].tokens)


# ----------------------------------------------------------------
# ingest_roadtools
# ----------------------------------------------------------------

class TestIngestRoadtools:
    def _write_roadtools(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / ".roadtools_auth"
        p.write_text(json.dumps(data))
        return p

    def test_access_token_ingested(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp(), "aud": GRAPH, "appid": FOCI_DEFAULT_CLIENT})
        data = {
            "_clientId": FOCI_DEFAULT_CLIENT,
            "_resource": GRAPH,
            "accessToken": jwt,
            "refreshToken": "0.rt-value",
            "tenantId": "t",
            "userId": "user@contoso.com",
            "isMRRT": True,
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        assert any(t.token_type == "access_token" for t in store.tokens)

    def test_refresh_token_ingested(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "_clientId": FOCI_DEFAULT_CLIENT,
            "_resource": GRAPH,
            "accessToken": jwt,
            "refreshToken": "0.rt-value",
            "tenantId": "t",
            "isMRRT": True,
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        assert any(t.token_type == "refresh_token" for t in store.tokens)

    def test_foci_set_from_is_mrrt(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "_clientId": "non-foci-client",
            "_resource": GRAPH,
            "accessToken": jwt,
            "refreshToken": "0.rt",
            "tenantId": "t",
            "isMRRT": True,
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        rt = next(t for t in store.tokens if t.token_type == "refresh_token")
        assert rt.foci is True

    def test_tenant_and_upn_set(self, tmp_path):
        jwt = _make_jwt({"tid": "tenant-xyz", "exp": _future_exp()})
        data = {
            "_clientId": FOCI_DEFAULT_CLIENT,
            "_resource": GRAPH,
            "accessToken": jwt,
            "tenantId": "tenant-xyz",
            "userId": "alice@example.com",
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        assert store.tenant_id == "tenant-xyz"
        assert store.user_upn == "alice@example.com"

    def test_expires_on_parsed(self, tmp_path):
        # expiresOn is a fallback — only used when the JWT has no exp claim.
        jwt = _make_jwt({"tid": "t", "aud": GRAPH})
        data = {
            "_clientId": FOCI_DEFAULT_CLIENT,
            "_resource": GRAPH,
            "accessToken": jwt,
            "tenantId": "t",
            "expiresOn": "2099-12-31 00:00:00",
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        at = next(t for t in store.tokens if t.token_type == "access_token")
        assert at.expires_at is not None
        assert at.expires_at.year == 2099

    def test_no_refresh_token_ok(self, tmp_path):
        jwt = _make_jwt({"tid": "t", "exp": _future_exp()})
        data = {
            "_clientId": FOCI_DEFAULT_CLIENT,
            "_resource": GRAPH,
            "accessToken": jwt,
            "tenantId": "t",
        }
        path = self._write_roadtools(tmp_path, data)
        store = ingest_roadtools(path)
        assert not any(t.token_type == "refresh_token" for t in store.tokens)
