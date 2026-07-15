"""Tests for format_credential_detail — the `creds <id>` detail view (Part 1)."""
from __future__ import annotations

from io import StringIO

from rich.console import Console

from quantum_mechanic.shell import formatters as f


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = f.console
    f.console = fake
    try:
        fn(*args, **kwargs)
    finally:
        f.console = orig
    return buf.getvalue()


def test_detail_shows_cred_id_and_provider_header():
    cred = {
        "id": 3,
        "provider": "entra",
        "credential_type": "token_store",
        "friendly_name": "alice@x.com",
        "status": "active",
    }
    out = _capture(f.format_credential_detail, cred, [])
    assert "#3" in out
    assert "ENTRA" in out
    assert "alice@x.com" in out


def test_detail_shows_derived_from_link_when_present():
    """OUTCOME: A credential with `derived_from_id` shows the parent link so
    operators can walk the pivot chain.
    """
    cred = {
        "id": 4,
        "provider": "entra",
        "credential_type": "token_store",
        "friendly_name": "alice@x.com",
        "status": "active",
        "derived_from_id": 2,
    }
    out = _capture(f.format_credential_detail, cred, [])
    assert "Derived from" in out
    assert "#2" in out


def test_detail_shows_expiration_and_resource_per_token():
    cred = {
        "id": 1, "provider": "entra", "credential_type": "token_store",
        "friendly_name": "alice@x.com", "status": "active",
    }
    details = [
        {
            "kind": "ARM AT",
            "resource": "https://management.azure.com",
            "token_type": "access_token",
            "foci": False,
            "client_id": "1950a258-227b-4e31-a9cf-717495945fc2",
            "expires_at": "2026-07-02T18:00:00+00:00",
            "minutes_remaining": 82,
            "is_expired": False,
            "scopes": [],
            "roles": [],
        },
        {
            "kind": "Graph AT",
            "resource": "https://graph.microsoft.com",
            "token_type": "access_token",
            "foci": False,
            "client_id": "1950a258",
            "expires_at": "2026-07-02T17:00:00+00:00",
            "minutes_remaining": 28,
            "is_expired": False,
            "scopes": ["User.Read", "Directory.Read.All"],
            "roles": [],
        },
    ]
    out = _capture(f.format_credential_detail, cred, details)
    # Resources shown compactly (https:// stripped).
    assert "management.azure.com" in out
    assert "graph.microsoft.com" in out
    # Kinds shown so operator maps back to acquire commands.
    assert "ARM AT" in out
    assert "Graph AT" in out
    # Minutes rendered.
    assert "82m" in out
    assert "28m" in out
    # Scopes shown for the graph token.
    assert "User.Read" in out
    assert "Directory.Read.All" in out


def test_detail_expired_token_marked_red():
    """OUTCOME: An expired token renders as 'expired' — not 'Nm' or blank.

    ANTI-GAMIFICATION: Silent rendering of an expired token as an active
    one would reintroduce the whole class of misleading UI this phase
    fights. If minutes_remaining <=0, kind is still shown but expiration
    reads 'expired'.
    """
    cred = {"id": 1, "provider": "entra", "credential_type": "token_store",
            "friendly_name": "x", "status": "active"}
    details = [{
        "kind": "Graph AT",
        "resource": "https://graph.microsoft.com",
        "token_type": "access_token",
        "foci": False,
        "client_id": "1950a258",
        "expires_at": "2020-01-01T00:00:00+00:00",
        "minutes_remaining": -60,
        "is_expired": True,
        "scopes": [],
        "roles": [],
    }]
    out = _capture(f.format_credential_detail, cred, details)
    assert "expired" in out


def test_format_credentials_hint_directs_to_detail_view():
    """OUTCOME: The compact `creds` output tells operators about `creds <id>`."""
    out = _capture(f.format_credentials, [
        {"id": 1, "provider": "entra", "credential_type": "token_store",
         "friendly_name": "x", "status": "active"},
    ])
    assert "creds <id>" in out
