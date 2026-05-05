# ================================================================
# TESTS: providers/entra/arm.py — ARM pagination helper
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from quantum_mechanic.providers.entra.arm import arm_list

_HEADERS = {"Authorization": "Bearer sometoken"}


def _mock_resp(status: int, body: dict) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = body
    m.text = str(body)
    return m


def _mock_http(*responses) -> MagicMock:
    http = MagicMock()
    http.get.side_effect = list(responses)
    return http


class TestArmListSinglePage:
    def test_returns_items(self):
        http = _mock_http(_mock_resp(200, {"value": [{"id": "a"}, {"id": "b"}]}))
        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == [{"id": "a"}, {"id": "b"}]

    def test_empty_value(self):
        http = _mock_http(_mock_resp(200, {"value": []}))
        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == []

    def test_missing_value_key(self):
        http = _mock_http(_mock_resp(200, {}))
        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == []

    def test_passes_headers(self):
        http = _mock_http(_mock_resp(200, {"value": []}))
        arm_list(http, "https://management.azure.com/x", _HEADERS)
        http.get.assert_called_once_with("https://management.azure.com/x", headers=_HEADERS)


class TestArmListPagination:
    def test_follows_next_link(self):
        page1 = _mock_resp(200, {
            "value": [{"id": "a"}],
            "nextLink": "https://management.azure.com/x?$skiptoken=abc",
        })
        page2 = _mock_resp(200, {"value": [{"id": "b"}]})
        http = _mock_http(page1, page2)

        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == [{"id": "a"}, {"id": "b"}]
        assert http.get.call_count == 2
        http.get.assert_any_call(
            "https://management.azure.com/x?$skiptoken=abc", headers=_HEADERS
        )

    def test_three_pages(self):
        pages = [
            _mock_resp(200, {"value": [{"id": str(i)}], "nextLink": f"https://x.com/p{i+1}"})
            for i in range(2)
        ] + [_mock_resp(200, {"value": [{"id": "2"}]})]
        http = _mock_http(*pages)

        result = arm_list(http, "https://x.com/p0", _HEADERS)
        assert len(result) == 3

    def test_stops_at_max_pages(self):
        # Every page has a nextLink — should stop at max_pages
        def _always_next(url, headers):
            return _mock_resp(200, {"value": [{"id": "x"}], "nextLink": url + "n"})

        http = MagicMock()
        http.get.side_effect = _always_next

        result = arm_list(http, "https://management.azure.com/x", _HEADERS, max_pages=3)
        assert len(result) == 3
        assert http.get.call_count == 3

    def test_null_next_link_stops(self):
        http = _mock_http(_mock_resp(200, {"value": [{"id": "a"}], "nextLink": None}))
        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == [{"id": "a"}]
        assert http.get.call_count == 1


class TestArmListErrors:
    def test_non_200_stops_immediately(self):
        http = _mock_http(_mock_resp(403, {"error": {"code": "AuthorizationFailed"}}))
        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == []

    def test_non_200_after_first_page_returns_partial(self):
        page1 = _mock_resp(200, {
            "value": [{"id": "a"}],
            "nextLink": "https://management.azure.com/x?page=2",
        })
        page2 = _mock_resp(500, {})
        http = _mock_http(page1, page2)

        result = arm_list(http, "https://management.azure.com/x", _HEADERS)
        assert result == [{"id": "a"}]
