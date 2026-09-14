"""Tests for scope-aware FOCI expansion (Task #2).

Guards the four outcome states of `try_acquire_scope`:
- granted           → token acquired, added to store, returned
- consent_required  → OAuth said "consent_required" — stop trying, tell operator
- invalid_grant     → RT is dead — stop trying, tell operator to re-auth
- unknown           → all clients tried without a grant and no terminal
                      classification (transient / unclassified AAD error)

ANTI-GAMIFICATION: If the module ever regresses to `.default` scope or
silently returns None on consent_required, these tests fail.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.scope_exchange import (
    ScopeExchangeResult,
    _v2_scope,
    try_acquire_scope,
)
from quantum_mechanic.providers.entra.token_store import (
    GRAPH,
    EntraToken,
    EntraTokenStore,
)


def _future(mins: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=mins)


def _make_jwt(claims: dict) -> str:
    """Build a minimal decodable JWT for token_from_jwt round-trip."""
    header = base64.urlsafe_b64encode(
        json.dumps({"typ": "JWT", "alg": "RS256"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def _store_with_foci_rt() -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-1", user_upn="alice@x.example")
    store.add_token(EntraToken(
        token_type="refresh_token",
        value="rt-value",
        resource="",
        tenant_id="tenant-1",
        client_id=FOCI_DEFAULT_CLIENT,
        foci=True,
        expires_at=_future(60 * 24 * 60),
    ))
    return store


def _fake_http(responses):
    """httpx.Client mock that returns `responses` in order for .post()."""
    http = MagicMock()
    http.post.side_effect = responses
    return http


def _resp(status_code: int = 200, body: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = body or {}
    r.text = ""
    return r


def test_v2_scope_composes_permission_correctly():
    """OUTCOME: _v2_scope emits the v2 endpoint's per-permission format,
    NOT `.default`. Regression guard for the whole point of the module."""
    scope = _v2_scope("https://graph.microsoft.com", "User.Read.All")
    assert scope == "https://graph.microsoft.com/User.Read.All openid offline_access"
    # Anti-gamification: must not contain the .default marker.
    assert ".default" not in scope


def test_no_foci_rt_returns_no_rt_status():
    """OUTCOME: A store with no FOCI RT → status='no_rt', no HTTP calls."""
    empty = EntraTokenStore(tenant_id="t", user_upn="x@y.example")
    result = try_acquire_scope(empty, "User.Read.All")
    assert result.status == "no_rt"
    assert result.token is None


def test_granted_returns_token_and_adds_to_store():
    """OUTCOME: First client returns a valid AT → status='granted', token
    is on the result and also added to the store."""
    store = _store_with_foci_rt()
    initial_count = len(store.tokens)

    access_jwt = _make_jwt({
        "aud": GRAPH,
        "scp": "User.Read.All",
        "exp": int(_future(50).timestamp()),
    })
    http = _fake_http([
        _resp(200, {"access_token": access_jwt}),
    ])

    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "granted"
    assert result.token is not None
    assert len(store.tokens) == initial_count + 1
    # The exact scope requested is what got sent to AAD.
    posted_scope = http.post.call_args[1]["data"]["scope"]
    assert "User.Read.All" in posted_scope
    assert ".default" not in posted_scope


def test_consent_required_stops_and_reports_terminal():
    """OUTCOME: consent_required error is TERMINAL — we stop trying other
    FOCI clients and return status='consent_required'. Retrying would waste
    AAD calls and delay the honest 'you need admin consent' message.
    """
    store = _store_with_foci_rt()
    http = _fake_http([
        _resp(400, {
            "error": "consent_required",
            "error_description": "AADSTS65001: user or admin has not consented",
        }),
    ])
    result = try_acquire_scope(store, "EntitlementManagement.Read.All", http=http)
    assert result.status == "consent_required"
    assert result.token is None
    # Only one client tried before terminal classification.
    assert len(result.tried_clients) == 1


def test_invalid_grant_stops_and_reports_terminal():
    """OUTCOME: invalid_grant → status='invalid_grant', don't retry."""
    store = _store_with_foci_rt()
    http = _fake_http([
        _resp(400, {"error": "invalid_grant", "error_description": "RT expired"}),
    ])
    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "invalid_grant"
    assert len(result.tried_clients) == 1


def test_non_terminal_error_falls_through_to_next_client():
    """OUTCOME: An unclassified error (e.g. 'invalid_scope') on client #1
    is NOT terminal — we try the next FOCI client. If that grants → success.
    """
    store = _store_with_foci_rt()

    access_jwt = _make_jwt({"aud": GRAPH, "exp": int(_future(50).timestamp())})
    http = _fake_http([
        _resp(400, {"error": "invalid_scope", "error_description": "not for this client"}),
        _resp(200, {"access_token": access_jwt}),
    ])
    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "granted"
    # At least two clients attempted before granting.
    assert len(result.tried_clients) >= 2


def test_all_clients_exhaust_with_unclassified_errors_returns_unknown():
    """OUTCOME: If every FOCI client returns a non-terminal, non-granting
    response, status='unknown' with the last error preserved."""
    store = _store_with_foci_rt()

    from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS
    responses = [
        _resp(400, {"error": "invalid_scope", "error_description": f"try #{i}"})
        for i in range(len(FOCI_CLIENT_IDS))
    ]
    http = _fake_http(responses)
    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "unknown"
    assert result.token is None
    assert "invalid_scope" in result.last_error


def test_throttling_429_falls_through_to_next_client():
    """OUTCOME: A 429 from client #1 doesn't blow up — we try client #2."""
    store = _store_with_foci_rt()

    access_jwt = _make_jwt({"aud": GRAPH, "exp": int(_future(50).timestamp())})
    http = _fake_http([
        _resp(429, {}),
        _resp(200, {"access_token": access_jwt}),
    ])
    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "granted"


def test_updated_refresh_token_gets_persisted_on_grant():
    """OUTCOME: If AAD returns a new refresh_token alongside the access_token,
    we add it to the store so subsequent expansions use the fresher RT."""
    store = _store_with_foci_rt()
    initial_rt = store.foci_refresh_token()
    assert initial_rt is not None

    access_jwt = _make_jwt({"aud": GRAPH, "exp": int(_future(50).timestamp())})
    new_rt_jwt = _make_jwt({
        "aud": GRAPH,
        "exp": int(_future(60 * 24 * 90).timestamp()),
        "appid": FOCI_DEFAULT_CLIENT,
    })
    http = _fake_http([
        _resp(200, {"access_token": access_jwt, "refresh_token": new_rt_jwt}),
    ])
    result = try_acquire_scope(store, "User.Read.All", http=http)
    assert result.status == "granted"
    # Store now contains at least two RT entries (original + new one on Graph
    # resource) — the add_token dedup keys on (type, resource) so a Graph-
    # scoped RT is a distinct row from the resource="" family RT.
    rt_count = sum(1 for t in store.tokens if t.token_type == "refresh_token")
    assert rt_count >= 2
