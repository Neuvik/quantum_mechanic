from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

from rich.console import Console

from quantum_mechanic.shell import commands_entra as ce


def _capture(args: list[str]) -> str:
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        ce.import_entra(MagicMock(), args)
    finally:
        ce.console = orig
    return buf.getvalue()


def test_import_entra_usage_mentions_browser_cdp():
    """OUTCOME: import usage teaches operators about the new browser-assisted path."""
    out = _capture([])
    assert "browser_cdp" in out
    assert "Chrome" in out or "Edge" in out


def test_import_entra_browser_cdp_prints_cross_platform_guidance():
    """OUTCOME: browser_cdp prints launch guidance plus the next-step workflow."""
    out = _capture(["browser_cdp", "--browser", "edge", "--os", "macos"])
    assert "remote-debugging-port" in out
    assert "import entra browser_cdp" in out
    assert "sign in" in out.lower()
    assert "Edge" in out


def test_import_entra_browser_cdp_rejects_unknown_browser():
    """OUTCOME: unsupported browser names fail cleanly."""
    out = _capture(["browser_cdp", "--browser", "firefox"])
    assert "Unsupported browser" in out


def test_import_entra_browser_cdp_rejects_unknown_os():
    """OUTCOME: unsupported OS selector fails cleanly."""
    out = _capture(["browser_cdp", "--os", "plan9"])
    assert "Unsupported OS" in out


def test_import_entra_browser_cdp_launches_temp_browser_when_requested():
    """OUTCOME: --launch starts a temp-profile browser instance and reports the port/profile."""
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        with patch(
            "quantum_mechanic.providers.entra.browser_cdp.launch_browser",
            return_value=MagicMock(
                port=9222,
                user_data_dir="/tmp/qm-edge-cdp-123",
                browser="edge",
                os_name="macos",
            ),
        ):
            ce.import_entra(MagicMock(), ["browser_cdp", "--browser", "edge", "--os", "macos", "--launch"])
    finally:
        ce.console = orig
    out = buf.getvalue()
    assert "Launched" in out
    assert "/tmp/qm-edge-cdp-123" in out
    assert "9222" in out


def test_import_entra_browser_cdp_attach_imports_store():
    """OUTCOME: --attach imports browser-derived token material into the workspace."""
    state = MagicMock()
    state.workspace = MagicMock()
    fake_store = MagicMock()
    fake_store.tokens = []

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
        return_value=(fake_store, {"browser_name": "Chrome/138.0.0.0"}),
    ) as mock_import, patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=7,
    ) as mock_persist, patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ) as mock_set_active, patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ) as mock_summary, patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        ce.import_entra(state, ["browser_cdp", "--attach", "--browser", "chrome", "--port", "9222"])

    mock_import.assert_called_once()
    mock_persist.assert_called_once_with(state, fake_store)
    mock_set_active.assert_called_once_with(state, 7, fake_store)
    mock_summary.assert_called_once_with(fake_store, 7)


def test_import_entra_browser_cdp_attach_reports_graph_ready_state():
    """OUTCOME: attach tells the operator when Graph is immediately usable."""
    state = MagicMock()
    state.workspace = MagicMock()
    fake_store = MagicMock()
    fake_store.tokens = []
    fake_store.best_token.return_value = object()

    out = StringIO()
    fake = Console(file=out, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        with patch(
            "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
            return_value=(fake_store, {"browser_name": "Chrome/138.0.0.0", "cookie_count": 3}),
        ), patch(
            "quantum_mechanic.shell.commands_entra._persist_store",
            return_value=7,
        ), patch(
            "quantum_mechanic.shell.commands_entra._set_active"
        ), patch(
            "quantum_mechanic.shell.commands_entra._print_import_summary"
        ):
            ce.import_entra(state, ["browser_cdp", "--attach", "--browser", "chrome", "--port", "9222"])
    finally:
        ce.console = orig

    text = out.getvalue()
    assert "Graph ready" in text
    assert "yes" in text.lower()


def test_import_entra_browser_cdp_attach_reports_cookie_only_state():
    """OUTCOME: attach warns cleanly when only cookies were imported and Graph is not ready."""
    state = MagicMock()
    state.workspace = MagicMock()
    fake_store = MagicMock()
    fake_store.tokens = []
    fake_store.best_token.return_value = None

    out = StringIO()
    fake = Console(file=out, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        with patch(
            "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
            return_value=(fake_store, {"browser_name": "Chrome/138.0.0.0", "cookie_count": 1}),
        ), patch(
            "quantum_mechanic.shell.commands_entra._persist_store",
            return_value=7,
        ), patch(
            "quantum_mechanic.shell.commands_entra._set_active"
        ), patch(
            "quantum_mechanic.shell.commands_entra._print_import_summary"
        ):
            ce.import_entra(state, ["browser_cdp", "--attach", "--browser", "chrome", "--port", "9222"])
    finally:
        ce.console = orig

    text = out.getvalue()
    assert "Graph ready" in text
    assert "not yet" in text.lower()


def test_import_entra_browser_cdp_attach_exchanges_ests_cookie_before_persist():
    """OUTCOME: attach turns imported ESTS cookies into a usable token response before save."""
    state = MagicMock()
    state.workspace = MagicMock()

    ests_token = MagicMock()
    ests_token.token_type = "ests_cookie"
    ests_token.value = "opaque-cookie"
    ests_token.tenant_id = "tenant-123"
    ests_token.raw_claims = {"cookie_name": "ESTSAUTH"}

    fake_store = MagicMock()
    fake_store.tokens = [ests_token]
    fake_store.tenant_id = "tenant-123"
    fake_store.prt_cookie.return_value = None

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
        return_value=(fake_store, {"browser_name": "Chrome/138.0.0.0"}),
    ), patch(
        "quantum_mechanic.providers.entra.exchange.exchange_ests_cookie",
        return_value={"access_token": "at", "refresh_token": "rt", "expires_in": 3600},
    ) as mock_exchange, patch(
        "quantum_mechanic.shell.commands_entra._apply_token_response"
    ) as mock_apply, patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=7,
    ), patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ), patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        ce.import_entra(state, ["browser_cdp", "--attach", "--browser", "chrome", "--port", "9222"])

    mock_exchange.assert_called_once()
    mock_apply.assert_called_once_with(
        fake_store,
        {"access_token": "at", "refresh_token": "rt", "expires_in": 3600},
        resource=ce._GRAPH,
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
    )
    assert mock_exchange.call_args.kwargs["cookie_name"] == "ESTSAUTH"


def test_import_entra_browser_cdp_attach_reports_origin_rejection_cleanly():
    """OUTCOME: attach origin-policy failures print a clean operator hint, not a traceback."""
    out = StringIO()
    fake = Console(file=out, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        with patch(
            "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
            side_effect=ValueError(
                "Chrome rejected the CDP websocket origin. Relaunch the browser with "
                "--remote-allow-origins=http://127.0.0.1:9222 and retry."
            ),
        ):
            ce.import_entra(MagicMock(), ["browser_cdp", "--attach", "--port", "9222"])
    finally:
        ce.console = orig

    text = out.getvalue()
    assert "rejected the CDP websocket origin" in text
    assert "Traceback" not in text


def test_import_entra_browser_cdp_attach_reports_cookie_surface_cleanly():
    """OUTCOME: no-cookie attach failures surface guidance and safe diagnostics."""
    out = StringIO()
    fake = Console(file=out, force_terminal=False, color_system=None, width=200)
    orig = ce.console
    ce.console = fake
    try:
        with patch(
            "quantum_mechanic.providers.entra.browser_cdp.import_browser_session",
            side_effect=ValueError(
                "No Microsoft auth cookies found in the attached browser session. "
                "Microsoft-adjacent cookies were visible on domains: login.microsoftonline.com. "
                "Names seen: fpc. Complete a real Microsoft sign-in flow in the launched temp profile "
                "(for example, https://login.microsoftonline.com/ or https://portal.azure.com/) and retry."
            ),
        ):
            ce.import_entra(MagicMock(), ["browser_cdp", "--attach", "--port", "9222"])
    finally:
        ce.console = orig

    text = out.getvalue()
    assert "No Microsoft auth cookies found" in text
    assert "login.microsoftonline.com" in text
    assert "Traceback" not in text
