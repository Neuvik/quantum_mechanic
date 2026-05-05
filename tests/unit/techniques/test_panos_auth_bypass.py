# ================================================================
# TESTS: quantum_mechanic.techniques.initial_access.panos_auth_bypass
# ----------------------------------------------------------------
# WHAT:   Unit tests for the PAN-OS CVE-2024-0012 + CVE-2024-9474
#         auth bypass + command injection chain.
#         All network I/O is mocked — no live target required.
#
# WHY:    Check mode is production-ready (ACCEPT). We need
#         deterministic coverage for all response variants:
#         vulnerable 200, patched 403, connection failures,
#         and the exploit chain's early-abort on non-vulnerable targets.
# ================================================================

from unittest.mock import MagicMock, call, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _ctx(target: str, safe_mode: bool = True) -> ExecutionContext:
    """Build a minimal ExecutionContext for testing."""
    ctx = MagicMock(spec=ExecutionContext)
    ctx.params = {"target": target, "timeout": 5, "verify_ssl": False}
    ctx.safe_mode = safe_mode
    ctx.log = lambda msg: None
    return ctx


# ================================================================
# Check mode tests
# ================================================================

class TestPANOSCheckMode:
    """Tests for the X-PAN-AUTHCHECK: off bypass probe (check mode)."""

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_vulnerable_200(self, mock_get):
        """A 200 response to the bypass probe confirms CVE-2024-0012 is present."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>PAN-OS content</html>"
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.1"))

        assert result["vulnerable"] is True
        assert result["mode"] == "check"
        assert result["evidence"]["response_status"] == 200
        assert result["cve"] == ["CVE-2024-0012", "CVE-2024-9474"]

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_not_vulnerable_403(self, mock_get):
        """A 403 Forbidden means the bypass header is blocked — patched."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.2"))

        assert result["vulnerable"] is False
        assert result["evidence"]["response_status"] == 403

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_not_vulnerable_302_redirect(self, mock_get):
        """A 302 to login page means auth is enforced — not vulnerable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.3"))

        assert result["vulnerable"] is False

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_connection_error(self, mock_get):
        """ConnectionError returns not-vulnerable without raising."""
        import requests as req

        mock_get.side_effect = req.ConnectionError("timed out")

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        result = _check(_ctx("https://192.0.2.1"))

        assert result["vulnerable"] is False
        assert "error" in result["evidence"]

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_timeout(self, mock_get):
        """Timeout returns not-vulnerable gracefully."""
        import requests as req

        mock_get.side_effect = req.Timeout("timed out")

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        result = _check(_ctx("https://10.0.0.10"))

        assert result["vulnerable"] is False
        assert "timed out" in result["evidence"]["error"].lower() or "timeout" in result["evidence"]["error"].lower()

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_check_sends_bypass_header(self, mock_get):
        """The bypass header X-PAN-AUTHCHECK: off is included in all check requests."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _check

        _check(_ctx("https://10.0.0.1"))

        call_kwargs = mock_get.call_args[1]
        headers = call_kwargs.get("headers", {})
        assert headers.get("X-PAN-AUTHCHECK") == "off"


# ================================================================
# Exploit mode tests
# ================================================================

class TestPANOSExploitMode:
    """Tests for the chained exploit (auth bypass + command injection)."""

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.post")
    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_exploit_aborts_if_check_fails(self, mock_get, mock_post):
        """If the auth bypass check fails (403), exploit mode aborts without injecting."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _exploit

        result = _exploit(_ctx("https://10.0.0.1", safe_mode=False))

        assert result["vulnerable"] is False
        # Should NOT have attempted the POST injection
        mock_post.assert_not_called()

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.time.sleep")
    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.post")
    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_exploit_rce_confirmed(self, mock_get, mock_post, mock_sleep):
        """When bypass + injection succeed and probe file returns id output — RCE confirmed."""
        # --------------------------------------------------------
        # Arrange: first GET = bypass confirmed (200),
        #          second GET = probe file read (200 with id output)
        # --------------------------------------------------------
        bypass_resp = MagicMock()
        bypass_resp.status_code = 200
        bypass_resp.text = "<html>bypass</html>"

        probe_resp = MagicMock()
        probe_resp.status_code = 200
        probe_resp.text = "uid=0(root) gid=0(root) groups=0(root)"

        mock_get.side_effect = [bypass_resp, probe_resp]

        post_resp = MagicMock()
        post_resp.status_code = 200
        mock_post.return_value = post_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import _exploit

        result = _exploit(_ctx("https://10.0.0.1", safe_mode=False))

        assert result["vulnerable"] is True
        assert "root" in result["evidence"]["rce_output"]
        assert result["mode"] == "exploit"
        assert len(result["artifacts"]) == 1


# ================================================================
# Execute dispatcher tests
# ================================================================

class TestPANOSExecute:
    """Tests for the top-level execute() dispatcher."""

    @patch("quantum_mechanic.techniques.initial_access.panos_auth_bypass.requests.get")
    def test_execute_safe_mode_routes_to_check(self, mock_get):
        """execute() with safe_mode=True routes to _check, no POST injection."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.panos_auth_bypass import execute

        result = execute(_ctx("https://10.0.0.1", safe_mode=True))

        assert result["mode"] == "check"
