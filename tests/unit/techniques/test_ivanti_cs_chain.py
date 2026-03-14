# ================================================================
# TESTS: quantum_mechanic.techniques.initial_access.ivanti_cs_chain
# ----------------------------------------------------------------
# WHAT:   Unit tests for the Ivanti Connect Secure CVE-2023-46805
#         + CVE-2024-21887 path traversal + command injection chain.
#         All network I/O is mocked — no live ICS appliance required.
#
# WHY:    Check mode is ACCEPT (production-ready). We need coverage
#         for the full matrix of ICS response shapes: JSON API body
#         (vulnerable), 302 login redirect (patched/not ICS),
#         401/403 (auth enforced), and transport errors. Exploit mode
#         is STAGING — we test the early-abort safety gate only.
# ================================================================

from unittest.mock import MagicMock, patch

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

class TestIvantiCSCheckMode:
    """Tests for the TOTP unauthenticated endpoint structural probe."""

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_vulnerable_json_api_response(self, mock_get):
        """A JSON API response from the TOTP endpoint confirms vulnerability."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.json.return_value = {
            "errorCode": "BACKUP_CODE_ERROR",
            "message": "Invalid backup code format",
        }
        mock_resp.text = '{"errorCode":"BACKUP_CODE_ERROR"}'
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        result = _check(_ctx("https://vpn.corp.com"))

        # --------------------------------------------------------
        # A JSON API body — even a 400 error — proves the API dispatcher
        # responded without requiring authentication.
        # --------------------------------------------------------
        assert result["vulnerable"] is True
        assert result["mode"] == "check"
        assert result["evidence"]["is_api_json"] is True
        assert result["cve"] == ["CVE-2023-46805", "CVE-2024-21887"]

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_not_vulnerable_login_redirect(self, mock_get):
        """A 302 redirect to the login page means auth is enforced — not vulnerable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {
            "Location": "/login",
            "Content-Type": "text/html",
        }
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        result = _check(_ctx("https://vpn.corp.com"))

        assert result["vulnerable"] is False
        assert result["evidence"]["response_status"] == 302

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_not_vulnerable_401(self, mock_get):
        """A 401 Unauthorized means auth is enforced."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "Unauthorized"
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        result = _check(_ctx("https://10.0.0.5"))

        assert result["vulnerable"] is False

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_connection_error(self, mock_get):
        """ConnectionError returns not-vulnerable without raising."""
        import requests as req

        mock_get.side_effect = req.ConnectionError("refused")

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        result = _check(_ctx("https://192.0.2.1"))

        assert result["vulnerable"] is False
        assert "error" in result["evidence"]

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_timeout(self, mock_get):
        """Timeout returns not-vulnerable gracefully."""
        import requests as req

        mock_get.side_effect = req.Timeout("timed out")

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        result = _check(_ctx("https://10.0.0.10"))

        assert result["vulnerable"] is False
        assert "timeout" in result["evidence"]["error"].lower() or "timed out" in result["evidence"]["error"].lower()

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_check_probe_url_uses_totp_endpoint(self, mock_get):
        """The check uses the TOTP endpoint, NOT the license API (no traversal in check)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _check

        _check(_ctx("https://10.0.0.1"))

        call_url = mock_get.call_args[0][0]
        # --------------------------------------------------------
        # Safety check: the probe must go to /api/v1/totp/user-backup-code/
        # NOT to the license or traversal path.
        # --------------------------------------------------------
        assert "/totp/user-backup-code/" in call_url
        assert "license" not in call_url
        assert "../" not in call_url


# ================================================================
# Exploit mode tests
# ================================================================

class TestIvantiCSExploitMode:
    """Tests for the chained path traversal + command injection exploit."""

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_exploit_aborts_if_check_fails(self, mock_get):
        """If the bypass check fails (401), exploit mode aborts without injecting."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _exploit

        result = _exploit(_ctx("https://10.0.0.1", safe_mode=False))

        assert result["vulnerable"] is False
        # Only 1 GET call (the check probe) — no injection URLs requested
        assert mock_get.call_count == 1

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.time.sleep")
    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_exploit_rce_confirmed_via_json_body(self, mock_get, mock_sleep):
        """RCE is confirmed when the id output appears in the ICS JSON error message."""
        # --------------------------------------------------------
        # Arrange: call sequence:
        #   1st GET = check (JSON API body → vulnerable)
        #   2nd GET = injection (any response)
        #   3rd GET = probe read (JSON with uid= in message)
        #   4th GET = cleanup (ignored)
        # --------------------------------------------------------
        check_resp = MagicMock()
        check_resp.status_code = 400
        check_resp.headers = {"Content-Type": "application/json"}
        check_resp.json.return_value = {"errorCode": "BACKUP_CODE_ERROR"}
        check_resp.text = '{"errorCode":"BACKUP_CODE_ERROR"}'

        inject_resp = MagicMock()
        inject_resp.status_code = 400
        inject_resp.headers = {"Content-Type": "application/json"}

        read_resp = MagicMock()
        read_resp.status_code = 400
        read_resp.headers = {"Content-Type": "application/json"}
        read_resp.json.return_value = {
            "errorCode": "NODE_ERROR",
            "message": "uid=0(root) gid=0(root) groups=0(root)",
        }

        cleanup_resp = MagicMock()
        cleanup_resp.status_code = 400

        mock_get.side_effect = [check_resp, inject_resp, read_resp, cleanup_resp]

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import _exploit

        result = _exploit(_ctx("https://10.0.0.1", safe_mode=False))

        assert result["vulnerable"] is True
        assert "root" in result["evidence"]["rce_output"]
        assert len(result["artifacts"]) == 1


# ================================================================
# Execute dispatcher tests
# ================================================================

class TestIvantiCSExecute:
    """Tests for the top-level execute() dispatcher."""

    @patch("quantum_mechanic.techniques.initial_access.ivanti_cs_chain.requests.get")
    def test_execute_safe_mode_routes_to_check(self, mock_get):
        """execute() with safe_mode=True routes to _check only — no injection."""
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        from quantum_mechanic.techniques.initial_access.ivanti_cs_chain import execute

        result = execute(_ctx("https://10.0.0.1", safe_mode=True))

        assert result["mode"] == "check"
        # Exactly one GET call — the check probe only
        assert mock_get.call_count == 1
