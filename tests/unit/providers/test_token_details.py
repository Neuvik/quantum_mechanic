"""Tests for EntraTokenStore.token_details() (Part 1 of creds display).

Guards the per-token detail structure that `creds <id>` renders.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import (
    ARM,
    GRAPH,
    EntraToken,
    EntraTokenStore,
)


def _future(mins: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=mins)


def _past(mins: int = 10) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=mins)


def _store_with(tokens: list[EntraToken]) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-1", user_upn="alice@x.example")
    for t in tokens:
        store.add_token(t)
    return store


def test_token_details_marks_kind_correctly_for_arm_and_graph_at():
    """OUTCOME: An ARM access token → kind='ARM AT'; a Graph AT → kind='Graph AT'."""
    store = _store_with([
        EntraToken(
            token_type="access_token", value="x", resource=ARM,
            tenant_id="t", client_id=FOCI_DEFAULT_CLIENT, expires_at=_future(80),
        ),
        EntraToken(
            token_type="access_token", value="x", resource=GRAPH,
            tenant_id="t", client_id=FOCI_DEFAULT_CLIENT, expires_at=_future(25),
        ),
    ])
    kinds = {d["kind"] for d in store.token_details()}
    assert "ARM AT" in kinds
    assert "Graph AT" in kinds


def test_token_details_foci_rt_marked_as_foci_rt():
    """OUTCOME: A refresh_token with foci=True → kind='FOCI RT'."""
    store = _store_with([
        EntraToken(
            token_type="refresh_token", value="x", resource="", tenant_id="t",
            client_id=FOCI_DEFAULT_CLIENT, foci=True, expires_at=_future(90 * 24 * 60),
        ),
    ])
    d = store.token_details()[0]
    assert d["kind"] == "FOCI RT"
    assert d["foci"] is True


def test_token_details_reports_minutes_remaining():
    """OUTCOME: minutes_remaining is populated so the formatter can color-code it."""
    store = _store_with([
        EntraToken(
            token_type="access_token", value="x", resource=GRAPH, tenant_id="t",
            client_id=FOCI_DEFAULT_CLIENT, expires_at=_future(30),
        ),
    ])
    d = store.token_details()[0]
    assert d["minutes_remaining"] is not None
    # Allow small drift — call may take a moment.
    assert 28 < d["minutes_remaining"] < 31


def test_token_details_flags_expired_tokens():
    """OUTCOME: Expired tokens ARE included (so operators can see them)
    but marked is_expired=True. ANTI-GAMIFICATION: hiding them would
    reintroduce the silent-failure class of bug this whole phase fights."""
    store = _store_with([
        EntraToken(
            token_type="access_token", value="x", resource=GRAPH, tenant_id="t",
            client_id=FOCI_DEFAULT_CLIENT, expires_at=_past(15),
        ),
    ])
    d = store.token_details()[0]
    assert d["is_expired"] is True
    assert d["kind"] == "Graph AT"


def test_token_details_parses_scp_claim_from_access_token():
    """OUTCOME: 'scp' claim from the JWT is exposed as `scopes` list.

    Uses token_from_jwt to build a real token so the claims path is exercised.
    """
    # Minimal JWT with scp claim; token_from_jwt handles decoding.
    import base64
    import json

    header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "RS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "aud": GRAPH,
        "scp": "User.Read Directory.Read.All Group.Read.All",
        "exp": int(_future(45).timestamp()),
    }).encode()).rstrip(b"=").decode()
    jwt = f"{header}.{payload}.signature"

    store = _store_with([
        EntraToken(
            token_type="access_token", value=jwt, resource=GRAPH, tenant_id="t",
            client_id=FOCI_DEFAULT_CLIENT, expires_at=_future(45),
        ),
    ])
    d = store.token_details()[0]
    assert "User.Read" in d["scopes"]
    assert "Directory.Read.All" in d["scopes"]
    assert "Group.Read.All" in d["scopes"]


def test_token_details_parses_roles_claim_for_application_perms():
    """OUTCOME: 'roles' claim (application permissions) is exposed as `roles` list."""
    import base64
    import json

    header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "RS256"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "aud": GRAPH,
        "roles": ["User.Read.All", "Directory.Read.All"],
        "exp": int(_future(45).timestamp()),
    }).encode()).rstrip(b"=").decode()
    jwt = f"{header}.{payload}.signature"

    store = _store_with([
        EntraToken(
            token_type="access_token", value=jwt, resource=GRAPH, tenant_id="t",
            client_id=FOCI_DEFAULT_CLIENT, expires_at=_future(45),
        ),
    ])
    d = store.token_details()[0]
    assert d["roles"] == ["User.Read.All", "Directory.Read.All"]
