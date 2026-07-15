"""Tests for graph_list typed-exception behavior.

Guards against the "silent 403" bug: graph_list must raise on first-page
failure so techniques can report status="denied" instead of returning
an empty list that looks like a successful zero-result enum.
"""
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.providers.entra.graph import (
    GraphAccessError,
    GraphError,
    GraphTransientError,
    graph_list,
)


def _mock_http(responses):
    """Build an httpx.Client mock that returns `responses` in order."""
    http = MagicMock()
    http.request.side_effect = responses
    return http


def _mock_response(status_code: int, body: dict | str = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text or (body if isinstance(body, str) else "")
    if isinstance(body, dict):
        resp.json.return_value = body
    else:
        resp.json.side_effect = ValueError("no json")
    resp.headers = {}
    return resp


def test_first_page_403_raises_access_error():
    """OUTCOME: HTTP 403 on the first page raises GraphAccessError.

    ANTI-GAMIFICATION: If someone reintroduces the "log and return []" bug,
    this test fails and prevents the silent-403 regression.
    """
    http = _mock_http([
        _mock_response(403, {
            "error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}
        }),
    ])
    with pytest.raises(GraphAccessError) as exc_info:
        graph_list(http, "https://graph.microsoft.com/v1.0/users", {})
    assert exc_info.value.status == 403
    assert "Authorization_RequestDenied" in str(exc_info.value) or exc_info.value.code == "Authorization_RequestDenied"


def test_first_page_401_raises_access_error():
    """OUTCOME: HTTP 401 also raises GraphAccessError (any 4xx)."""
    http = _mock_http([_mock_response(401, {"error": {"code": "InvalidAuthenticationToken", "message": "expired"}})])
    with pytest.raises(GraphAccessError) as exc_info:
        graph_list(http, "https://graph.microsoft.com/v1.0/users", {})
    assert exc_info.value.status == 401


def test_first_page_5xx_raises_transient_error():
    """OUTCOME: HTTP 503 after retries raises GraphTransientError, not access."""
    http = _mock_http([
        _mock_response(503, "backend down"),
        _mock_response(503, "backend down"),
        _mock_response(503, "backend down"),
    ])
    with pytest.raises(GraphTransientError) as exc_info:
        graph_list(http, "https://graph.microsoft.com/v1.0/users", {})
    assert exc_info.value.status == 503


def test_later_page_failure_returns_partial_items():
    """OUTCOME: If page 1 succeeds and page 2 returns 403, return what page 1 gave us.

    This preserves the original graph_list contract of best-effort partial return
    when data has already been collected — only the first-page silent-503 is a bug.
    """
    http = _mock_http([
        _mock_response(200, {
            "value": [{"id": "a"}, {"id": "b"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=xyz",
        }),
        _mock_response(403, {"error": {"code": "Authorization_RequestDenied"}}),
    ])
    items = graph_list(http, "https://graph.microsoft.com/v1.0/users", {})
    assert len(items) == 2


def test_error_carries_url_status_code_message():
    """OUTCOME: The raised exception preserves url, status, code, message for reporting."""
    http = _mock_http([_mock_response(403, {
        "error": {"code": "Authorization_RequestDenied", "message": "The caller is not authorized"}
    })])
    with pytest.raises(GraphAccessError) as exc_info:
        graph_list(http, "https://graph.microsoft.com/v1.0/users?$top=100", {})
    err = exc_info.value
    assert err.url == "https://graph.microsoft.com/v1.0/users?$top=100"
    assert err.status == 403
    assert err.code == "Authorization_RequestDenied"
    assert err.message == "The caller is not authorized"


def test_unparseable_body_falls_back_to_sentinel_code():
    """OUTCOME: When the 4xx response body is not valid JSON, code falls back to a sentinel."""
    resp = MagicMock()
    resp.status_code = 403
    resp.text = "<html>gateway rejected</html>"
    resp.headers = {}
    resp.json.side_effect = ValueError("no json")
    http = _mock_http([resp])
    with pytest.raises(GraphAccessError) as exc_info:
        graph_list(http, "https://graph.microsoft.com/v1.0/users", {})
    assert exc_info.value.code in ("Unknown", "Unparseable", None) or exc_info.value.code == "Unknown"


def test_scope_hint_populated_from_url():
    """OUTCOME: When URL matches a known scope-hint prefix, error carries scope_hint."""
    http = _mock_http([_mock_response(403, {
        "error": {"code": "Authorization_RequestDenied"}
    })])
    with pytest.raises(GraphAccessError) as exc_info:
        graph_list(
            http,
            "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages",
            {},
        )
    assert exc_info.value.scope_hint == "EntitlementManagement.Read.All"


def test_all_errors_subclass_grapherror():
    """OUTCOME: Both GraphAccessError and GraphTransientError inherit from GraphError."""
    assert issubclass(GraphAccessError, GraphError)
    assert issubclass(GraphTransientError, GraphError)
