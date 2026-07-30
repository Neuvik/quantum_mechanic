# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_whoami
# ================================================================

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_whoami import execute


# ----------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------

def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _make_access_token(device_claims: bool = False, foci: bool = True) -> EntraToken:
    return EntraToken(
        token_type="access_token",
        value="eyJ.fake.access",
        resource=GRAPH,
        tenant_id="tenant-123",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
        device_claims=device_claims,
        foci=foci,
        raw_claims={"tid": "tenant-123", "oid": "user-oid-1", "amr": ["mfa"]},
    )


def _make_foci_refresh_token() -> EntraToken:
    return EntraToken(
        token_type="refresh_token",
        value="0.fake-rt",
        resource=GRAPH,
        tenant_id="tenant-123",
        client_id=FOCI_DEFAULT_CLIENT,
        foci=True,
    )


def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-123", user_upn="alice@contoso.com")
    if token:
        store.add_token(token)
    return store


_ME_RESPONSE = {
    "id": "user-oid-1",
    "userPrincipalName": "alice@contoso.com",
    "displayName": "Alice",
    "jobTitle": "Engineer",
    "department": "Security",
    "tenantId": "tenant-123",
}

_MEMBER_OF_RESPONSE = {
    "value": [
        {"@odata.type": "#microsoft.graph.group", "id": "grp-1", "displayName": "Security Team"},
        {"@odata.type": "#microsoft.graph.group", "id": "grp-2", "displayName": "Entra Admins"},
    ]
}

_DIR_ROLES_RESPONSE = {
    "value": [
        {"id": "role-1", "displayName": "Global Administrator", "roleTemplateId": "62e90394-..."},
    ]
}

_OWNED_OBJECTS_RESPONSE = {
    "value": [
        {
            "@odata.type": "#microsoft.graph.application",
            "id": "app-id-1",
            "displayName": "Owned App",
            "appId": "client-id-1",
        }
    ]
}


def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "entra"
    ctx.session = store
    ctx.log_api_call = MagicMock()
    return ctx


def _mock_http_responses(*responses) -> MagicMock:
    """Return a context manager mock whose .get() returns each response in sequence."""
    mock_responses = []
    for status, body in responses:
        r = MagicMock()
        r.status_code = status
        r.json.return_value = body
        mock_responses.append(r)

    http_instance = MagicMock()
    http_instance.get.side_effect = mock_responses
    http_instance.__enter__ = lambda s: http_instance
    http_instance.__exit__ = MagicMock(return_value=False)
    return http_instance


# ----------------------------------------------------------------
# No token
# ----------------------------------------------------------------

class TestNoToken:
    def test_returns_error_when_no_token(self):
        store = _make_store()  # empty
        ctx = _build_ctx(store)
        result = execute(ctx)
        assert "error" in result
        assert "No Graph token" in result["error"]


# ----------------------------------------------------------------
# Success path — direct access token
# ----------------------------------------------------------------

class TestSuccessWithAccessToken:
    def _run(self, device_claims: bool = False, foci: bool = True):
        store = _make_store(_make_access_token(device_claims=device_claims, foci=foci))
        ctx = _build_ctx(store)
        http = _mock_http_responses(
            (200, _ME_RESPONSE),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (200, _OWNED_OBJECTS_RESPONSE),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            return execute(ctx)

    def test_principal_id(self):
        result = self._run()
        assert result["principal_id"] == "user-oid-1"

    def test_tenant_id(self):
        result = self._run()
        assert result["tenant_id"] == "tenant-123"

    def test_me_populated(self):
        result = self._run()
        assert result["me"]["displayName"] == "Alice"
        assert result["me"]["jobTitle"] == "Engineer"

    def test_groups_populated(self):
        result = self._run()
        assert len(result["groups"]) == 2
        names = {g["displayName"] for g in result["groups"]}
        assert "Security Team" in names

    def test_directory_roles_populated(self):
        result = self._run()
        assert len(result["directory_roles"]) == 1
        assert result["directory_roles"][0]["displayName"] == "Global Administrator"

    def test_owned_objects_populated(self):
        result = self._run()
        assert len(result["owned_objects"]) == 1
        assert result["owned_objects"][0]["displayName"] == "Owned App"

    def test_owned_objects_empty_on_403(self):
        """OUTCOME: owned_objects defaults to [] when /me/ownedObjects returns non-200."""
        store = _make_store(_make_access_token())
        ctx = _build_ctx(store)
        http = _mock_http_responses(
            (200, _ME_RESPONSE),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (403, {"error": {"code": "Forbidden"}}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)
        assert result["owned_objects"] == []

    def test_tenant_id_prefers_token_claim_over_common_placeholder(self):
        """OUTCOME: when store.tenant_id is still the "common" placeholder
        (set at acquisition time when no specific tenant was pinned), the
        real tenant GUID decoded from the access token's `tid` claim wins,
        and store.tenant_id gets corrected to match."""
        store = EntraTokenStore(tenant_id="common", user_upn="alice@contoso.com")
        store.add_token(_make_access_token())  # raw_claims tid == "tenant-123"
        ctx = _build_ctx(store)
        http = _mock_http_responses(
            (200, {**_ME_RESPONSE, "tenantId": None}),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (200, _OWNED_OBJECTS_RESPONSE),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)
        assert result["tenant_id"] == "tenant-123"
        assert store.tenant_id == "tenant-123"

    def test_posture_mfa_from_claims(self):
        result = self._run()
        assert result["posture"]["mfa"] is True

    def test_posture_device_claims_false(self):
        result = self._run(device_claims=False)
        assert result["posture"]["device_claims"] is False

    def test_posture_device_claims_true(self):
        result = self._run(device_claims=True)
        assert result["posture"]["device_claims"] is True

    def test_posture_foci(self):
        result = self._run(foci=True)
        assert result["posture"]["foci_token"] is True

    def test_store_upn_synced_back(self):
        store = EntraTokenStore(tenant_id="tenant-123")  # no upn
        store.add_token(_make_access_token())
        ctx = _build_ctx(store)
        http = _mock_http_responses(
            (200, _ME_RESPONSE),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (200, {"value": []}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            execute(ctx)
        assert store.user_upn == "alice@contoso.com"


# ----------------------------------------------------------------
# FOCI refresh token path
# ----------------------------------------------------------------

class TestFociExpansion:
    def test_expands_foci_refresh_token(self):
        store = _make_store(_make_foci_refresh_token())
        ctx = _build_ctx(store)

        expanded_token = _make_access_token()

        http = _mock_http_responses(
            (200, _ME_RESPONSE),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (200, {"value": []}),
        )
        with patch(
            "quantum_mechanic.techniques.discovery.entra_whoami.foci_expand",
            return_value=expanded_token,
        ), patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)

        assert "error" not in result
        assert result["me"]["displayName"] == "Alice"

    def test_error_when_foci_expansion_fails(self):
        store = _make_store(_make_foci_refresh_token())
        ctx = _build_ctx(store)

        with patch("quantum_mechanic.techniques.discovery.entra_whoami.foci_expand", return_value=None):
            result = execute(ctx)

        assert "error" in result
        assert "FOCI expansion" in result["error"]


# ----------------------------------------------------------------
# Graph errors
# ----------------------------------------------------------------

class TestGraphErrors:
    def test_non_200_me_gracefully_handled(self):
        store = _make_store(_make_access_token())
        ctx = _build_ctx(store)

        http = _mock_http_responses(
            (403, {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}),
            (200, _MEMBER_OF_RESPONSE),
            (200, _DIR_ROLES_RESPONSE),
            (200, {"value": []}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)

        # Should still return a result dict — no exception
        assert isinstance(result, dict)
        assert result["me"] == {}  # empty since /me failed

    def test_non_200_member_of_gracefully_handled(self):
        store = _make_store(_make_access_token())
        ctx = _build_ctx(store)

        http = _mock_http_responses(
            (200, _ME_RESPONSE),
            (403, {"error": {"code": "Forbidden"}}),
            (200, _DIR_ROLES_RESPONSE),
            (200, {"value": []}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)

        assert result["groups"] == []
        assert result["me"]["displayName"] == "Alice"

    def test_principal_type_service_principal_when_no_upn(self):
        store = EntraTokenStore(tenant_id="tenant-123")
        token = EntraToken(
            token_type="access_token",
            value="eyJ.fake.sp",
            resource=GRAPH,
            tenant_id="tenant-123",
            expires_at=_future(),
            raw_claims={"tid": "tenant-123", "oid": "sp-oid"},
        )
        store.add_token(token)
        ctx = _build_ctx(store)

        me_no_upn = {
            "id": "sp-oid",
            "displayName": "My App",
            "tenantId": "tenant-123",
        }
        http = _mock_http_responses(
            (200, me_no_upn),
            (200, {"value": []}),
            (200, {"value": []}),
            (200, {"value": []}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            result = execute(ctx)

        assert result["principal_type"] == "service_principal"


# ----------------------------------------------------------------
# MFA posture detection
# ----------------------------------------------------------------

class TestMfaPosture:
    def _run_with_amr(self, amr: list[str]) -> dict:
        store = EntraTokenStore(tenant_id="t")
        token = EntraToken(
            token_type="access_token",
            value="eyJ.fake",
            resource=GRAPH,
            tenant_id="t",
            expires_at=_future(),
            raw_claims={"tid": "t", "oid": "u", "amr": amr},
        )
        store.add_token(token)
        ctx = _build_ctx(store)
        http = _mock_http_responses(
            (200, {"id": "u", "tenantId": "t"}),
            (200, {"value": []}),
            (200, {"value": []}),
            (200, {"value": []}),
        )
        with patch("quantum_mechanic.techniques.discovery.entra_whoami.httpx.Client", return_value=http):
            return execute(ctx)

    def test_mfa_true_when_mfa_in_amr(self):
        result = self._run_with_amr(["pwd", "mfa"])
        assert result["posture"]["mfa"] is True

    def test_mfa_true_when_ngcmfa_in_amr(self):
        result = self._run_with_amr(["pwd", "ngcmfa"])
        assert result["posture"]["mfa"] is True

    def test_mfa_false_when_only_pwd(self):
        result = self._run_with_amr(["pwd"])
        assert result["posture"]["mfa"] is False

    def test_mfa_none_when_no_amr(self):
        result = self._run_with_amr([])
        assert result["posture"]["mfa"] is None
