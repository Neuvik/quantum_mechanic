# ================================================================
# TESTS: quantum_mechanic.techniques.initial_access.fortios_auth_bypass
# ----------------------------------------------------------------
# WHAT:   Unit tests for the FortiOS CVE-2024-55591 auth bypass
#         technique. Tests check mode (unauthenticated probe) and
#         graceful failure paths. All network I/O is mocked.
#
# WHY:    Check mode is production-ready (ACCEPT verdict). We need
#         deterministic coverage over the vulnerable/patched/error
#         paths without needing a live FortiOS appliance.
#         Exploit mode is STAGING — covered by manual validation only.
# ================================================================

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext


# ----------------------------------------------------------------
# Helpers — build a minimal ExecutionContext w/o a real workspace
# ----------------------------------------------------------------

def _ctx(target: str, safe_mode: bool = True) -> ExecutionContext:
    """Build a minimal ExecutionContext for testing."""
    ctx = MagicMock(spec=ExecutionContext)
    ctx.params = {"target": target, "timeout": 5, "verify_ssl": False}
    ctx.safe_mode = safe_mode
    ctx.log = lambda msg: None  # Suppress log output in tests
    return ctx


# ================================================================
# Check mode tests
# ================================================================

class TestFortiOSCheckMode:
    """Tests for the unauthenticated monitor API probe (check mode)."""

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_vulnerable_200(self, mock_get):
        """A 200 response with FortiOS status JSON marks target as vulnerable."""
        # --------------------------------------------------------
        # Arrange: mock a 200 with a JSON body containing 'version'
        # as returned by vulnerable FortiOS 7.0.x
        # --------------------------------------------------------
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "version": "v7.0.14",
                "serial": "FGT60F1234567890",
                "hostname": "corp-fw-01",
            }
        }
        mock_resp.text = '{"results": {"version": "v7.0.14"}}'
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.1"))

        # --------------------------------------------------------
        # Assert: should detect as vulnerable and extract version
        # --------------------------------------------------------
        assert result["vulnerable"] is True
        assert result["mode"] == "check"
        assert result["evidence"]["response_status"] == 200
        assert result["evidence"]["version_detected"] == "v7.0.14"
        assert result["cve"] == ["CVE-2024-55591"]

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_not_vulnerable_401(self, mock_get):
        """A 401 response means the patch is applied — not vulnerable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.2"))

        assert result["vulnerable"] is False
        assert result["mode"] == "check"
        assert result["evidence"]["response_status"] == 401

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_not_vulnerable_403(self, mock_get):
        """A 403 response (restricted by local-in-policy) is not vulnerable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.3"))

        assert result["vulnerable"] is False

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_connection_error(self, mock_get):
        """A ConnectionError means the target is unreachable — not vulnerable, no crash."""
        import requests as req

        mock_get.side_effect = req.ConnectionError("Connection refused")

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        result = _check(_ctx("https://192.0.2.1"))  # TEST-NET — guaranteed unreachable

        # --------------------------------------------------------
        # Assert: function returns gracefully without raising
        # --------------------------------------------------------
        assert result["vulnerable"] is False
        assert "error" in result["evidence"]
        assert "Connection" in result["evidence"]["error"]

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_timeout(self, mock_get):
        """A Timeout returns not-vulnerable gracefully."""
        import requests as req

        mock_get.side_effect = req.Timeout("timed out")

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        result = _check(_ctx("https://10.0.10.10"))

        assert result["vulnerable"] is False
        assert "timed out" in result["evidence"]["error"].lower() or "timeout" in result["evidence"]["error"].lower()

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_check_target_url_stripped(self, mock_get):
        """Trailing slashes on target URL are stripped before building probe URL."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import _check

        _check(_ctx("https://10.0.0.1///"))  # Triple trailing slash

        # --------------------------------------------------------
        # Confirm: the URL passed to requests.get has no double-slashes
        # --------------------------------------------------------
        call_url = mock_get.call_args[0][0]
        assert "//api" not in call_url
        assert call_url.startswith("https://10.0.0.1/api/")


# ================================================================
# Execute dispatcher tests
# ================================================================

class TestFortiOSExecute:
    """Tests for the top-level execute() dispatcher."""

    @patch("quantum_mechanic.techniques.initial_access.fortios_auth_bypass.requests.get")
    def test_execute_safe_mode_routes_to_check(self, mock_get):
        """execute() with safe_mode=True routes to _check without calling exploit."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.fortios_auth_bypass import execute

        result = execute(_ctx("https://10.0.0.1", safe_mode=True))

        assert result["mode"] == "check"
        # Only one GET call (check mode), no WebSocket interaction
        assert mock_get.call_count == 1

    def test_execute_exploit_mode_without_websocket_client(self):
        """execute() with safe_mode=False degrades gracefully if websocket-client missing."""
        # --------------------------------------------------------
        # Simulate import failure for websocket-client by patching
        # the import inside the module namespace.
        # --------------------------------------------------------
        import builtins

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "websocket":
                raise ImportError("No module named 'websocket'")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            from quantum_mechanic.techniques.initial_access import fortios_auth_bypass
            import importlib
            importlib.reload(fortios_auth_bypass)
            result = fortios_auth_bypass._exploit(_ctx("https://10.0.0.1", safe_mode=False))

        assert result["vulnerable"] is None or result["evidence"].get("staging") is True
        assert "websocket" in result["evidence"]["error"].lower()
