from __future__ import annotations

from unittest.mock import MagicMock, patch

from websocket._exceptions import WebSocketBadStatusException

from quantum_mechanic.providers.entra.browser_cdp import (
    build_launch_plan,
    import_browser_session,
    launch_browser,
)


def test_build_launch_plan_macos_edge_uses_app_bundle_binary():
    """OUTCOME: macOS Edge guidance uses the app-bundle executable path."""
    plan = build_launch_plan(browser="edge", os_name="macos")
    assert "Microsoft Edge.app/Contents/MacOS/Microsoft Edge" in plan.command
    assert "--remote-debugging-port=9222" in plan.command


def test_build_launch_plan_linux_chrome_uses_tmp_profile():
    """OUTCOME: Linux Chrome guidance uses a separate tmp profile dir."""
    plan = build_launch_plan(browser="chrome", os_name="linux")
    assert plan.command.startswith("google-chrome ")
    assert "--user-data-dir=/tmp/qm-chrome-cdp" in plan.command


def test_build_launch_plan_windows_edge_uses_powershell_style_command():
    """OUTCOME: Windows Edge guidance is emitted as a PowerShell command."""
    plan = build_launch_plan(browser="edge", os_name="windows")
    assert "$Env:ProgramFiles(x86)" in plan.command
    assert "msedge.exe" in plan.command
    assert "$Env:TEMP\\qm-edge-cdp" in plan.command


def test_build_launch_plan_honors_browser_path_override():
    """OUTCOME: operator-supplied browser path overrides the default path."""
    plan = build_launch_plan(
        browser="chrome",
        os_name="linux",
        browser_path="/opt/google/chrome/chrome",
    )
    assert plan.command.startswith("/opt/google/chrome/chrome ")


def test_build_launch_plan_honors_port_and_profile_override():
    """OUTCOME: explicit port/profile overrides flow into the launch command."""
    plan = build_launch_plan(
        browser="edge",
        os_name="macos",
        port=9333,
        user_data_dir="/tmp/qm-custom-profile",
    )
    assert "--remote-debugging-port=9333" in plan.command
    assert "--user-data-dir=/tmp/qm-custom-profile" in plan.command
    assert "--remote-allow-origins=http://127.0.0.1:9333" in plan.command


def test_launch_browser_creates_temp_profile_and_spawns_process():
    """OUTCOME: launch_browser creates a temp profile dir and starts the browser."""
    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.tempfile.mkdtemp",
        return_value="/tmp/qm-edge-cdp-abc123",
    ), patch(
        "quantum_mechanic.providers.entra.browser_cdp.subprocess.Popen",
        return_value=MagicMock(),
    ) as mock_popen:
        plan = launch_browser(browser="edge", os_name="linux")

    assert plan.user_data_dir == "/tmp/qm-edge-cdp-abc123"
    argv = mock_popen.call_args.args[0]
    assert argv[0] == "microsoft-edge"
    assert "--remote-debugging-port=9222" in argv
    assert "--user-data-dir=/tmp/qm-edge-cdp-abc123" in argv
    assert "--remote-allow-origins=http://127.0.0.1:9222" in argv


def test_import_browser_session_collects_ests_cookies_into_store():
    """OUTCOME: CDP attach yields an EntraTokenStore populated from ESTS cookies."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    ws = MagicMock()
    ws.recv.side_effect = [
        '{"id":1,"result":{"cookies":[{"name":"ESTSAUTHPERSISTENT","value":"opaque-cookie","domain":".login.microsoftonline.com"}]}}'
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        return_value=ws,
    ):
        store, meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    assert meta["browser_name"] == "Chrome/138.0.0.0"
    assert len(store.tokens) == 1
    assert store.tokens[0].token_type == "ests_cookie"
    assert store.tokens[0].value == "opaque-cookie"
    assert store.tokens[0].raw_claims["cookie_name"] == "ESTSAUTHPERSISTENT"
    assert store.tokens[0].raw_claims["cookie_domain"] == ".login.microsoftonline.com"


def test_import_browser_session_ignores_non_microsoft_cookies():
    """OUTCOME: only Microsoft auth cookies are ingested from the browser cookie jar."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Microsoft Edge/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    ws = MagicMock()
    ws.recv.side_effect = [
        '{"id":1,"result":{"cookies":['
        '{"name":"sessionid","value":"nope","domain":".example.com"},'
        '{"name":"ESTSAUTH","value":"keep-me","domain":".login.microsoftonline.com"}'
        ']}}'
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        return_value=ws,
    ):
        store, meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    assert meta["browser_name"] == "Microsoft Edge/138.0.0.0"
    assert len(store.tokens) == 1
    assert store.tokens[0].value == "keep-me"


def test_import_browser_session_accepts_known_ests_cookie_on_office_domain():
    """OUTCOME: known ESTS cookie names import even when hosted on Office domains."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    ws = MagicMock()
    ws.recv.side_effect = [
        '{"id":1,"result":{"cookies":['
        '{"name":"ESTSAUTHPERSISTENT","value":"office-cookie","domain":".outlook.office.com"}'
        ']}}'
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        return_value=ws,
    ):
        store, meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    assert meta["browser_name"] == "Chrome/138.0.0.0"
    assert len(store.tokens) == 1
    assert store.tokens[0].token_type == "ests_cookie"
    assert store.tokens[0].value == "office-cookie"


def test_import_browser_session_prefers_real_page_targets_over_browser_target():
    """OUTCOME: browser CDP attach walks real page targets when browser-scope cookies are empty."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    list_resp = MagicMock()
    list_resp.json.return_value = [
        {
            "id": "1",
            "type": "page",
            "url": "devtools://devtools/bundled/devtools_app.html",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/devtools",
        },
        {
            "id": "2",
            "type": "page",
            "url": "https://outlook.office365.com/mail/",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/outlook",
        },
    ]
    http = MagicMock()
    http.get.side_effect = [version_resp, list_resp]

    browser_ws = MagicMock()
    browser_ws.recv.side_effect = ['{"id":1,"result":{"cookies":[]}}']
    page_ws = MagicMock()
    page_ws.recv.side_effect = [
        '{"id":1,"result":{}}',
        '{"id":2,"result":{"cookies":[{"name":"ESTSAUTHPERSISTENT","value":"page-cookie","domain":".outlook.office.com"}]}}',
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        side_effect=[browser_ws, page_ws],
    ):
        store, meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    assert len(store.tokens) == 1
    assert store.tokens[0].value == "page-cookie"
    assert meta["cookie_count"] == 1


def test_import_browser_session_skips_devtools_and_browser_ui_targets():
    """OUTCOME: only real http(s) page targets are queried for page-scope cookie collection."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    list_resp = MagicMock()
    list_resp.json.return_value = [
        {
            "id": "devtools",
            "type": "page",
            "url": "devtools://devtools/bundled/devtools_app.html",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/devtools",
        },
        {
            "id": "browser-ui",
            "type": "browser_ui",
            "url": "chrome://omnibox-popup.top-chrome/",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/browser-ui",
        },
        {
            "id": "real-page",
            "type": "page",
            "url": "https://myapps.microsoft.com/",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/real-page",
        },
    ]
    http = MagicMock()
    http.get.side_effect = [version_resp, list_resp]

    browser_ws = MagicMock()
    browser_ws.recv.side_effect = ['{"id":1,"result":{"cookies":[]}}']
    page_ws = MagicMock()
    page_ws.recv.side_effect = [
        '{"id":1,"result":{}}',
        '{"id":2,"result":{"cookies":[{"name":"ESTSAUTH","value":"myapps-cookie","domain":".myapps.microsoft.com"}]}}',
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        side_effect=[browser_ws, page_ws],
    ) as mock_conn:
        store, _meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    assert len(store.tokens) == 1
    assert store.tokens[0].value == "myapps-cookie"
    assert mock_conn.call_count == 2


def test_import_browser_session_aggregates_importable_cookies_across_page_targets():
    """OUTCOME: attach collects importable ESTS cookies from multiple real page targets."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    list_resp = MagicMock()
    list_resp.json.return_value = [
        {
            "id": "page-1",
            "type": "page",
            "url": "https://outlook.office365.com/mail/",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
        },
        {
            "id": "page-2",
            "type": "page",
            "url": "https://myapps.microsoft.com/",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-2",
        },
    ]
    http = MagicMock()
    http.get.side_effect = [version_resp, list_resp]

    browser_ws = MagicMock()
    browser_ws.recv.side_effect = ['{"id":1,"result":{"cookies":[]}}']
    page1_ws = MagicMock()
    page1_ws.recv.side_effect = [
        '{"id":1,"result":{}}',
        '{"id":2,"result":{"cookies":[{"name":"ESTSAUTH","value":"auth-cookie","domain":".login.microsoftonline.com"}]}}',
    ]
    page2_ws = MagicMock()
    page2_ws.recv.side_effect = [
        '{"id":1,"result":{}}',
        '{"id":2,"result":{"cookies":[{"name":"ESTSAUTHPERSISTENT","value":"persistent-cookie","domain":".login.microsoftonline.com"}]}}',
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        side_effect=[browser_ws, page1_ws, page2_ws],
    ):
        store, meta = import_browser_session(http=http, host="127.0.0.1", port=9222)

    cookie_names = {t.raw_claims.get("cookie_name") for t in store.tokens if t.token_type == "ests_cookie"}
    assert cookie_names == {"ESTSAUTH", "ESTSAUTHPERSISTENT"}
    assert meta["cookie_count"] == 2


def test_import_browser_session_surfaces_origin_rejection_cleanly():
    """OUTCOME: Chrome origin-policy rejection becomes an actionable operator error."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        side_effect=WebSocketBadStatusException(
            "Handshake status 403 Forbidden",
            403,
            {},
            b"Rejected an incoming WebSocket connection",
        ),
    ):
        try:
            import_browser_session(http=http, host="127.0.0.1", port=9222)
        except ValueError as exc:
            msg = str(exc)
        else:
            raise AssertionError("Expected ValueError")

    assert "rejected the CDP websocket origin" in msg
    assert "--remote-allow-origins=http://127.0.0.1:9222" in msg


def test_import_browser_session_guides_when_no_microsoft_cookies_exist():
    """OUTCOME: empty/non-Microsoft cookie jars return an operator-guidance error."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    ws = MagicMock()
    ws.recv.side_effect = [
        '{"id":1,"result":{"cookies":[{"name":"sessionid","value":"nope","domain":".example.com"}]}}'
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        return_value=ws,
    ):
        try:
            import_browser_session(http=http, host="127.0.0.1", port=9222)
        except ValueError as exc:
            msg = str(exc)
        else:
            raise AssertionError("Expected ValueError")

    assert "No Microsoft auth cookies found" in msg
    assert "login.microsoftonline.com" in msg
    assert "portal.azure.com" in msg


def test_import_browser_session_reports_microsoft_adjacent_cookie_surface():
    """OUTCOME: operator sees safe cookie-name/domain diagnostics when allowlist misses."""
    version_resp = MagicMock()
    version_resp.json.return_value = {
        "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc",
        "Browser": "Chrome/138.0.0.0",
    }
    http = MagicMock()
    http.get.return_value = version_resp

    ws = MagicMock()
    ws.recv.side_effect = [
        '{"id":1,"result":{"cookies":['
        '{"name":"fpc","value":"opaque","domain":".login.microsoftonline.com"},'
        '{"name":"stsservicecookie","value":"opaque2","domain":".portal.azure.com"}'
        ']}}'
    ]

    with patch(
        "quantum_mechanic.providers.entra.browser_cdp.websocket.create_connection",
        return_value=ws,
    ):
        try:
            import_browser_session(http=http, host="127.0.0.1", port=9222)
        except ValueError as exc:
            msg = str(exc)
        else:
            raise AssertionError("Expected ValueError")

    assert "Microsoft-adjacent cookies were visible" in msg
    assert "login.microsoftonline.com" in msg
    assert "portal.azure.com" in msg
    assert "fpc" in msg
    assert "stsservicecookie" in msg
