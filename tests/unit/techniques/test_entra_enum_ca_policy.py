"""Tests for discovery/entra_enum_ca_policy per-policy drilldown."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.techniques.discovery.entra_enum_ca_policy import execute


def _ctx(id_val: str = None, name_val: str = None) -> MagicMock:
    ctx = MagicMock()
    ctx.get_param.side_effect = lambda k: {"id": id_val, "name": name_val}.get(k)
    fake_token = MagicMock()
    fake_token.value = "fake"
    fake_token.token_type = "access_token"
    ctx.session.best_token.return_value = fake_token
    return ctx


def test_no_selector_returns_error():
    """OUTCOME: neither --id nor --name provided → status='error'."""
    ctx = _ctx()
    result = execute(ctx)
    assert result["status"] == "error"
    assert "--id" in result["error"] and "--name" in result["error"]


def test_id_lookup_happy_path():
    """OUTCOME: --id fetches the policy directly and returns it."""
    ctx = _ctx(id_val="pol-1")

    class FakeHTTP:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            assert url.endswith("/policies/pol-1")
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {
                "id": "pol-1",
                "displayName": "Block Legacy Auth",
                "state": "enabled",
                "conditions": {"users": {}},
            }
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.httpx.Client", return_value=FakeHTTP()):
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["policy"]["displayName"] == "Block Legacy Auth"


def test_id_lookup_404_returns_not_found():
    """OUTCOME: 404 on /policies/<id> → status='error' with 'not found' in message."""
    ctx = _ctx(id_val="missing")

    class FakeHTTP:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            r = MagicMock()
            r.status_code = 404
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.httpx.Client", return_value=FakeHTTP()):
        result = execute(ctx)

    assert result["status"] == "error"
    assert "not found" in result["error"].lower()


def test_name_lookup_returns_single_match():
    """OUTCOME: --name uses list + case-insensitive substring match, returns single hit."""
    ctx = _ctx(name_val="mfa")

    class FakeHTTP:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None):
            r = MagicMock()
            r.status_code = 200
            return r

    with patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.httpx.Client", return_value=FakeHTTP()), \
         patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.graph_list") as mock_list:
        mock_list.return_value = [
            {"id": "1", "displayName": "MFA for All Users", "state": "enabled"},
            {"id": "2", "displayName": "Block Legacy Auth", "state": "enabled"},
        ]
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["policy"]["displayName"] == "MFA for All Users"


def test_name_lookup_multiple_matches_returns_error():
    """OUTCOME: When --name matches >1 policy, ask for --id disambiguation."""
    ctx = _ctx(name_val="policy")

    class FakeHTTP:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url, headers=None): return None

    with patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.httpx.Client", return_value=FakeHTTP()), \
         patch("quantum_mechanic.techniques.discovery.entra_enum_ca_policy.graph_list") as mock_list:
        mock_list.return_value = [
            {"id": "1", "displayName": "Policy One", "state": "enabled"},
            {"id": "2", "displayName": "Policy Two", "state": "enabled"},
        ]
        result = execute(ctx)

    assert result["status"] == "error"
    assert "--id" in result["error"]
    assert "2" in result["error"]  # count in message
