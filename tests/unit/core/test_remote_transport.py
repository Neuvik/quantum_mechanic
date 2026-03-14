# ================================================================
# TESTS: quantum_mechanic.core.transport — RemoteTransport
# ----------------------------------------------------------------
# WHAT:  Contract tests for RemoteTransport. Verifies that
#        RemoteTransport satisfies the same Transport ABC as
#        LocalTransport: correct result shaping, no raised exceptions,
#        and correct HTTP wire calls to qmd.
#
# ANTI-GAMIFICATION:
#   - We do NOT mock TechniqueRunner or LocalTransport.
#   - We mock at the httpx.Client boundary — the actual HTTP wire.
#   - The mocked responses match exactly what qmd returns (verified
#     by test_server.py which runs against the real FastAPI app).
#
# TDD STATUS: RED — RemoteTransport does not exist yet.
#
# LAYERS:
#   Layer 1 — Contract : same interface as LocalTransport
#   Layer 4 — Security : expired/tampered token rejected at construction
#   Layer 5 — Chaos    : network errors, malformed responses
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.daemon.pki import EngagementCA, OperatorToken, issue_operator_token


# ================================================================
# Fixtures
# ================================================================

@pytest.fixture
def engagement_ca() -> EngagementCA:
    return EngagementCA(engagement="op-test")


@pytest.fixture
def valid_token(engagement_ca) -> OperatorToken:
    return issue_operator_token(
        ca=engagement_ca,
        operator="alice",
        host="qmd.example.com:8443",
        engagement="op-test",
        expires_days=30,
    )


@pytest.fixture
def expired_token(engagement_ca) -> OperatorToken:
    """A token that expired 1 second ago."""
    tok = issue_operator_token(
        ca=engagement_ca,
        operator="alice",
        host="qmd.example.com:8443",
        engagement="op-test",
        expires_days=30,
    )
    # Force expiry into the past
    tok.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    return tok


def _mock_httpx_client(
    techniques_payload: list[dict] | None = None,
    run_payload: dict | None = None,
    operators_payload: list[dict] | None = None,
) -> MagicMock:
    """
    Build a mock httpx.Client that returns realistic qmd responses.

    Keyed by last URL path segment so the same mock handles both endpoints.
    """
    client = MagicMock()

    def _get(url, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "operators" in url:
            resp.json.return_value = operators_payload or []
        else:
            # /techniques (with or without ?provider=)
            resp.json.return_value = techniques_payload or [
                {
                    "id": "discovery/whoami",
                    "tactic": "discovery",
                    "providers": ["aws", "azure", "gcp", "oci"],
                    "severity": "info",
                    "safe": True,
                    "description": "Who am I?",
                }
            ]
        return resp

    def _post(url, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = run_payload or {
            "technique_id": "discovery/whoami",
            "status": "success",
            "operator": "alice",
            "provider": "aws",
            "data": None,
            "error": None,
            "timestamp": "2026-03-09T00:00:00+00:00",
        }
        return resp

    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get = _get
    client.post = _post
    return client


# ================================================================
# CONTRACT: RemoteTransport satisfies the Transport ABC
# ================================================================

class TestRemoteTransportContract:
    """
    SCENARIO: Operator connects to qmd with a valid token.
    OUTCOME:  RemoteTransport behaves identically to LocalTransport
              from the caller's perspective.
    """

    def test_can_construct_from_valid_token(self, valid_token):
        """
        OUTCOME: RemoteTransport can be instantiated from a valid OperatorToken.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        rt = RemoteTransport(valid_token)
        assert rt is not None

    def test_can_construct_from_token_string(self, valid_token):
        """
        OUTCOME: RemoteTransport also accepts a encoded token string (qm://...).
        """
        from quantum_mechanic.core.transport import RemoteTransport
        token_str = valid_token.encode()
        rt = RemoteTransport(token_str)
        assert rt is not None

    def test_list_techniques_returns_metadata_objects(self, valid_token):
        """
        OUTCOME: list_techniques() yields TechniqueMetadata — same type as LocalTransport.
        """
        from quantum_mechanic.core.technique import TechniqueMetadata
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = _mock_httpx_client()
        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            techs = list(rt.list_techniques())

        assert len(techs) > 0
        for t in techs:
            assert isinstance(t, TechniqueMetadata), f"Expected TechniqueMetadata, got {type(t)}"

    def test_list_techniques_has_required_fields(self, valid_token):
        """
        OUTCOME: Each TechniqueMetadata from the remote has 'id' and 'providers'.
        """
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = _mock_httpx_client()
        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            techs = list(rt.list_techniques())

        for t in techs:
            assert hasattr(t, "id")
            assert hasattr(t, "providers")

    def test_list_techniques_provider_filter_is_forwarded(self, valid_token):
        """
        OUTCOME: list_techniques(provider='aws') adds ?provider=aws to the request.
        """
        from quantum_mechanic.core.transport import RemoteTransport

        captured_calls = []

        mock_client = _mock_httpx_client(techniques_payload=[
            {"id": "discovery/whoami", "tactic": "discovery", "providers": ["aws"],
             "severity": "info", "safe": True, "description": "Who am I?"}
        ])
        original_get = mock_client.get
        def capturing_get(url, **kwargs):
            captured_calls.append(url)
            return original_get(url, **kwargs)
        mock_client.get = capturing_get

        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            list(rt.list_techniques(provider="aws"))

        assert any("aws" in call for call in captured_calls), (
            f"Expected ?provider=aws in URL, got: {captured_calls}"
        )

    def test_run_technique_returns_technique_result(self, valid_token):
        """
        OUTCOME: run_technique() returns a TechniqueResult — never raises.
        """
        from quantum_mechanic.core.runner import TechniqueResult
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = _mock_httpx_client()
        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            result = rt.run_technique("discovery/whoami")

        assert isinstance(result, TechniqueResult)

    def test_run_technique_result_has_required_fields(self, valid_token):
        """
        OUTCOME: TechniqueResult has technique_id, status, and provider.
        """
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = _mock_httpx_client()
        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            result = rt.run_technique("discovery/whoami")

        assert result.technique_id == "discovery/whoami"
        assert result.status in ("success", "error", "skipped")
        assert result.provider is not None

    def test_run_technique_never_raises(self, valid_token):
        """
        OUTCOME: Even when the server returns an error body, run_technique
                 never raises — it returns status='error'.
        """
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = _mock_httpx_client(run_payload={
            "technique_id": "does/not/exist",
            "status": "error",
            "operator": "alice",
            "provider": "unknown",
            "data": None,
            "error": "Technique not found.",
            "timestamp": "2026-03-09T00:00:00+00:00",
        })
        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            result = rt.run_technique("does/not/exist")

        assert result.status == "error"
        assert result.technique_id == "does/not/exist"

    def test_operator_is_derived_from_token(self, valid_token):
        """
        OUTCOME: RemoteTransport knows who it's operating as.
        This is important for audit attribution.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        rt = RemoteTransport(valid_token)
        assert rt.operator == "alice"

    def test_host_is_derived_from_token(self, valid_token):
        """
        OUTCOME: RemoteTransport knows which host to connect to.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        rt = RemoteTransport(valid_token)
        assert "qmd.example.com" in rt.host


# ================================================================
# SECURITY: Token validation at construction
# ================================================================

class TestRemoteTransportSecurity:
    """
    SCENARIO: Operator tries to connect with an expired or bad token.
    OUTCOME:  RemoteTransport raises TokenError at construction time,
              before any network connection is made.
    """

    def test_expired_token_raises_at_construction(self, expired_token):
        """
        OUTCOME: Constructing RemoteTransport with an expired token raises TokenError.
        No network call should be made.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        from quantum_mechanic.daemon.pki import TokenError

        with pytest.raises(TokenError, match="expired"):
            RemoteTransport(expired_token)

    def test_expired_token_string_raises_at_construction(self, expired_token):
        """
        OUTCOME: Constructing RemoteTransport from an expired encoded string raises TokenError.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        from quantum_mechanic.daemon.pki import TokenError

        # Encode it (the token object is valid Python, just expired)
        token_str = expired_token.encode()

        with pytest.raises(TokenError, match="expired"):
            RemoteTransport(token_str)

    def test_garbage_string_raises_at_construction(self):
        """
        OUTCOME: A garbage string raises TokenError, not a generic ValueError.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        from quantum_mechanic.daemon.pki import TokenError

        with pytest.raises(TokenError):
            RemoteTransport("this-is-not-a-token")

    def test_missing_scheme_raises_token_error(self):
        """
        OUTCOME: A base64 blob without the qm:// scheme raises TokenError.
        """
        from quantum_mechanic.core.transport import RemoteTransport
        from quantum_mechanic.daemon.pki import TokenError
        import base64, json

        bad = base64.b64encode(json.dumps({"operator": "x"}).encode()).decode()
        with pytest.raises(TokenError):
            RemoteTransport(bad)


# ================================================================
# CHAOS: Network failure handling
# ================================================================

class TestRemoteTransportChaos:
    """
    SCENARIO: Network blips, timeouts, server 500s.
    OUTCOME:  run_technique() never raises — always returns TechniqueResult.
              list_techniques() returns empty iterator on network failure,
              does not raise.
    """

    def test_network_error_on_run_returns_error_result(self, valid_token):
        """
        OUTCOME: If the HTTP call to qmd raises (connection refused, timeout),
                 run_technique() returns status='error' with a helpful message.
        """
        import httpx
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post = MagicMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            result = rt.run_technique("discovery/whoami")

        assert result.status == "error"
        assert "Connection refused" in (result.error or "") or "connect" in (result.error or "").lower()

    def test_network_error_on_list_returns_empty(self, valid_token):
        """
        OUTCOME: If GET /techniques fails, list_techniques() yields nothing.
        Does NOT raise to the caller.
        """
        import httpx
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            techs = list(rt.list_techniques())  # must not raise

        assert techs == []

    def test_malformed_json_response_on_run_returns_error(self, valid_token):
        """
        OUTCOME: If qmd returns unexpected JSON shape, run_technique() returns
                 status='error', not an AttributeError or KeyError.
        """
        from quantum_mechanic.core.transport import RemoteTransport

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        bad_resp = MagicMock()
        bad_resp.raise_for_status = MagicMock()
        bad_resp.json.return_value = {"unexpected": "shape"}  # missing required fields
        mock_client.post = MagicMock(return_value=bad_resp)

        with patch("quantum_mechanic.core.transport.RemoteTransport._make_client",
                   return_value=mock_client):
            rt = RemoteTransport(valid_token)
            result = rt.run_technique("discovery/whoami")

        assert result.status == "error"
