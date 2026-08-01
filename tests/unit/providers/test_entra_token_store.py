# ================================================================
# TEST: quantum_mechanic.providers.entra.token_store
# ================================================================

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS, FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import (
    GRAPH,
    ARM,
    CAP_ERRORS,
    EntraDeviceState,
    EntraToken,
    EntraTokenStore,
    decode_jwt_claims,
    token_from_jwt,
)


# ----------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------

def _future(minutes: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def _past(minutes: int = 10) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _make_access_token(
    resource: str = GRAPH,
    expired: bool = False,
    device_claims: bool = False,
    foci: bool = False,
    client_id: str = FOCI_DEFAULT_CLIENT,
    tenant_id: str = "tenant-123",
) -> EntraToken:
    return EntraToken(
        token_type="access_token",
        value="eyJ.fake.access",
        resource=resource,
        tenant_id=tenant_id,
        client_id=client_id,
        expires_at=_past() if expired else _future(),
        device_claims=device_claims,
        foci=foci,
    )


def _make_refresh_token(foci: bool = True) -> EntraToken:
    return EntraToken(
        token_type="refresh_token",
        value="0.fake-refresh-token",
        resource=GRAPH,
        tenant_id="tenant-123",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(minutes=129600),  # 90 days
        device_claims=False,
        foci=foci,
    )


def _make_store_with_access() -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-123", user_upn="user@contoso.com")
    store.add_token(_make_access_token())
    return store


def _make_store_with_foci_refresh() -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-123", user_upn="user@contoso.com")
    store.add_token(_make_refresh_token(foci=True))
    return store


# ----------------------------------------------------------------
# EntraToken
# ----------------------------------------------------------------

class TestEntraToken:
    def test_is_expired_future(self):
        tok = _make_access_token()
        assert tok.is_expired is False

    def test_is_expired_past(self):
        tok = _make_access_token(expired=True)
        assert tok.is_expired is True

    def test_is_expired_no_expiry(self):
        tok = EntraToken(token_type="ests_cookie", value="x", resource="")
        assert tok.is_expired is False

    def test_minutes_remaining_future(self):
        tok = _make_access_token()
        assert tok.minutes_remaining is not None
        assert 55 < tok.minutes_remaining < 65

    def test_minutes_remaining_none(self):
        tok = EntraToken(token_type="ests_cookie", value="x", resource="")
        assert tok.minutes_remaining is None


# ----------------------------------------------------------------
# EntraTokenStore — token selection
# ----------------------------------------------------------------

class TestEntraTokenStore:
    def test_best_token_direct_access(self):
        store = _make_store_with_access()
        tok = store.best_token(GRAPH)
        assert tok is not None
        assert tok.token_type == "access_token"

    def test_best_token_skips_expired(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_access_token(expired=True))
        assert store.best_token(GRAPH) is None

    def test_best_token_falls_back_to_foci(self):
        store = _make_store_with_foci_refresh()
        tok = store.best_token(GRAPH)
        # No direct access token — should return the FOCI refresh token
        assert tok is not None
        assert tok.token_type == "refresh_token"
        assert tok.foci is True

    def test_best_token_returns_none_when_empty(self):
        store = EntraTokenStore(tenant_id="t")
        assert store.best_token(GRAPH) is None

    def test_add_token_deduplicates(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_access_token())
        store.add_token(_make_access_token())  # same type + resource
        assert len([t for t in store.tokens if t.token_type == "access_token"]) == 1

    def test_add_token_keeps_different_resources(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_access_token(resource=GRAPH))
        store.add_token(_make_access_token(resource=ARM))
        assert len(store.tokens) == 2

    def test_add_token_keeps_distinct_ests_cookies_by_cookie_name(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(
            EntraToken(
                token_type="ests_cookie",
                value="cookie-1",
                resource="",
                raw_claims={"cookie_name": "ESTSAUTHPERSISTENT"},
            )
        )
        store.add_token(
            EntraToken(
                token_type="ests_cookie",
                value="cookie-2",
                resource="",
                raw_claims={"cookie_name": "ESTSAUTH"},
            )
        )
        assert len([t for t in store.tokens if t.token_type == "ests_cookie"]) == 2

    def test_add_token_replaces_same_ests_cookie_name(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(
            EntraToken(
                token_type="ests_cookie",
                value="cookie-1",
                resource="",
                raw_claims={"cookie_name": "ESTSAUTHPERSISTENT"},
            )
        )
        store.add_token(
            EntraToken(
                token_type="ests_cookie",
                value="cookie-2",
                resource="",
                raw_claims={"cookie_name": "ESTSAUTHPERSISTENT"},
            )
        )
        cookies = [t for t in store.tokens if t.token_type == "ests_cookie"]
        assert len(cookies) == 1
        assert cookies[0].value == "cookie-2"

    def test_foci_refresh_token_found(self):
        store = _make_store_with_foci_refresh()
        assert store.foci_refresh_token() is not None

    def test_foci_refresh_token_not_found(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_refresh_token(foci=False))
        assert store.foci_refresh_token() is None

    def test_has_device_claims_true(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_access_token(device_claims=True))
        assert store.has_device_claims() is True

    def test_has_device_claims_false(self):
        store = _make_store_with_access()
        assert store.has_device_claims() is False

    def test_can_satisfy_joined_device_cap_via_token(self):
        store = EntraTokenStore(tenant_id="t")
        store.add_token(_make_access_token(device_claims=True))
        assert store.can_satisfy_joined_device_cap() is True

    def test_can_satisfy_joined_device_cap_via_device(self):
        store = EntraTokenStore(tenant_id="t")
        store.device = EntraDeviceState(
            device_id="dev-1",
            device_cert_pem="cert",
            transport_key_pem="key",
            tenant_id="t",
            enrolled_at=datetime.now(timezone.utc),
            join_type="azureADJoined",
        )
        assert store.can_satisfy_joined_device_cap() is True

    def test_can_satisfy_joined_device_cap_false(self):
        store = _make_store_with_access()
        assert store.can_satisfy_joined_device_cap() is False

    def test_prt_material_found(self):
        store = EntraTokenStore(tenant_id="t")
        prt = EntraToken(
            token_type="prt_with_key",
            value="raw-prt-value",
            resource="",
            raw_claims={"session_key": "abc123", "tenant_id": "t"},
        )
        store.add_token(prt)
        assert store.prt_material() is not None
        assert store.prt_material().raw_claims["session_key"] == "abc123"

    def test_prt_material_not_found(self):
        store = _make_store_with_access()
        assert store.prt_material() is None


# ----------------------------------------------------------------
# CAP guidance
# ----------------------------------------------------------------

class TestCapGuidance:
    def test_aadsts53003(self):
        guidance = EntraTokenStore.cap_guidance("AADSTS53003")
        assert guidance is not None
        assert "AADSTS53003" in guidance
        assert "device_enroll" in guidance

    def test_aadsts53000(self):
        guidance = EntraTokenStore.cap_guidance("AADSTS53000")
        assert guidance is not None
        assert "Joined" in guidance

    def test_aadsts50076(self):
        guidance = EntraTokenStore.cap_guidance("AADSTS50076")
        assert guidance is not None
        assert "MFA" in guidance

    def test_unknown_error(self):
        assert EntraTokenStore.cap_guidance("AADSTS99999") is None

    def test_guidance_in_description_string(self):
        # AADSTS code embedded in a longer error description string
        guidance = EntraTokenStore.cap_guidance(
            "AADSTS53003: The user is not authorized to access this resource. "
            "AADSTS Trace ID: abc"
        )
        assert guidance is not None


# ----------------------------------------------------------------
# Serialization round-trip
# ----------------------------------------------------------------

class TestSerialization:
    def test_round_trip_with_access_token(self):
        store = _make_store_with_access()
        restored = EntraTokenStore.from_dict(store.to_dict())
        assert restored.tenant_id == store.tenant_id
        assert restored.user_upn == store.user_upn
        assert len(restored.tokens) == 1
        tok = restored.tokens[0]
        assert tok.token_type == "access_token"
        assert tok.resource == GRAPH

    def test_round_trip_with_device_state(self):
        store = EntraTokenStore(tenant_id="t", user_upn="u@t.com")
        store.device = EntraDeviceState(
            device_id="dev-123",
            device_cert_pem="-----BEGIN CERTIFICATE-----",
            transport_key_pem="-----BEGIN RSA PRIVATE KEY-----",
            tenant_id="t",
            enrolled_at=datetime(2026, 4, 30, 12, 0, 0, tzinfo=timezone.utc),
            join_type="azureADJoined",
        )
        restored = EntraTokenStore.from_dict(store.to_dict())
        assert restored.device is not None
        assert restored.device.device_id == "dev-123"
        assert restored.device.join_type == "azureADJoined"

    def test_round_trip_expires_at_preserved(self):
        store = _make_store_with_access()
        original_expiry = store.tokens[0].expires_at
        restored = EntraTokenStore.from_dict(store.to_dict())
        assert restored.tokens[0].expires_at == original_expiry

    def test_empty_store_round_trip(self):
        store = EntraTokenStore()
        restored = EntraTokenStore.from_dict(store.to_dict())
        assert restored.tokens == []
        assert restored.device is None


# ----------------------------------------------------------------
# .roadtools_auth export
# ----------------------------------------------------------------

class TestRoadtoolsExport:
    def test_export_format_keys(self):
        store = EntraTokenStore(tenant_id="tenant-123", user_upn="u@t.com")
        store.add_token(_make_access_token())
        store.add_token(_make_refresh_token())
        result = store.export_roadtools_auth()

        required_keys = {
            "_clientId", "_resource", "accessToken", "refreshToken",
            "idToken", "tokenType", "expiresOn", "tenantId", "userId",
            "isMRRT", "_authority",
        }
        assert required_keys.issubset(result.keys())

    def test_export_tenant_id(self):
        store = EntraTokenStore(tenant_id="tenant-abc", user_upn="u@t.com")
        store.add_token(_make_access_token(tenant_id="tenant-abc"))
        store.add_token(_make_refresh_token())
        result = store.export_roadtools_auth()
        assert result["tenantId"] == "tenant-abc"

    def test_export_is_mrrt_true_for_foci(self):
        store = EntraTokenStore(tenant_id="t", user_upn="u@t.com")
        store.add_token(_make_access_token())
        store.add_token(_make_refresh_token(foci=True))
        result = store.export_roadtools_auth()
        assert result["isMRRT"] is True

    def test_export_raises_with_no_tokens(self):
        store = EntraTokenStore(tenant_id="t")
        with pytest.raises(ValueError, match="No token available"):
            store.export_roadtools_auth()

    def test_export_authority_format(self):
        store = EntraTokenStore(tenant_id="my-tenant")
        store.add_token(_make_access_token())
        result = store.export_roadtools_auth()
        assert "my-tenant" in result["_authority"]
        assert result["_authority"].startswith("https://login.microsoftonline.com/")


# ----------------------------------------------------------------
# JWT utilities
# ----------------------------------------------------------------

class TestJwtUtilities:
    def _make_jwt(self, payload: dict) -> str:
        import base64
        import json
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        return f"{header}.{body}.fakesig"

    def test_decode_jwt_claims(self):
        jwt = self._make_jwt({"oid": "abc", "tid": "tenant-1", "exp": 9999999999})
        claims = decode_jwt_claims(jwt)
        assert claims["oid"] == "abc"
        assert claims["tid"] == "tenant-1"

    def test_decode_invalid_jwt_returns_empty(self):
        assert decode_jwt_claims("not.a.jwt.at.all.extra") == {}
        assert decode_jwt_claims("onlyone") == {}

    def test_token_from_jwt_access(self):
        payload = {
            "oid": "user-1",
            "tid": "tenant-1",
            "exp": int((_future()).timestamp()),
            "aud": GRAPH,
            "appid": FOCI_DEFAULT_CLIENT,
            "scp": "User.Read Group.Read.All",
        }
        jwt = self._make_jwt(payload)
        tok = token_from_jwt(jwt, "access_token", resource=GRAPH)
        assert tok.token_type == "access_token"
        assert tok.resource == GRAPH
        assert tok.tenant_id == "tenant-1"
        assert tok.foci is True  # FOCI_DEFAULT_CLIENT is a known FOCI member
        assert "User.Read" in tok.scopes

    def test_token_from_jwt_device_claims(self):
        payload = {
            "tid": "t",
            "exp": int(_future().timestamp()),
            "aud": GRAPH,
            "deviceid": "device-abc",
            "join_type": "1",
        }
        jwt = self._make_jwt(payload)
        tok = token_from_jwt(jwt, "access_token", resource=GRAPH)
        assert tok.device_claims is True

    def test_token_from_jwt_no_device_claims(self):
        payload = {
            "tid": "t",
            "exp": int(_future().timestamp()),
            "aud": GRAPH,
        }
        jwt = self._make_jwt(payload)
        tok = token_from_jwt(jwt, "access_token", resource=GRAPH)
        assert tok.device_claims is False


# ----------------------------------------------------------------
# FOCI client ID table
# ----------------------------------------------------------------

class TestFociClientIds:
    def test_has_at_least_seven_members(self):
        """OUTCOME: The table must have AT LEAST the 7 baseline apps.

        Previously this asserted exactly 7 — that hardcoded assumption
        broke the moment we started sourcing from the vendored community
        list (~49 apps). The invariant we actually care about is that the
        baseline never regresses.
        """
        assert len(FOCI_CLIENT_IDS) >= 7

    def test_default_client_in_table(self):
        assert FOCI_DEFAULT_CLIENT in FOCI_CLIENT_IDS

    def test_known_apps_present(self):
        names = list(FOCI_CLIENT_IDS.values())
        assert "Microsoft Office" in names

    def test_community_list_augments_baseline(self):
        """OUTCOME: The vendored community list adds substantially more FOCI
        clients than the 7-app baseline. If vendoring silently regresses,
        this test surfaces it — the whole point of vendoring was coverage.
        """
        assert len(FOCI_CLIENT_IDS) > 20, (
            f"Expected community list to add many FOCI apps beyond the "
            f"7-app baseline; got only {len(FOCI_CLIENT_IDS)}. "
            "Refs vendoring may be broken — run tools/update_entra_refs.py."
        )
        names = list(FOCI_CLIENT_IDS.values())
        assert "Microsoft Teams" in names
        assert "OneDrive" in names
        assert "Microsoft Teams" in names
        assert "OneDrive" in names
