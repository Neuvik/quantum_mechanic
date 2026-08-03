from __future__ import annotations

from dataclasses import dataclass
import json
import platform
import subprocess
import tempfile
from typing import Any

import httpx
import websocket

from quantum_mechanic.providers.entra.ingest import ingest_ests_cookie, ingest_prt_cookie
from quantum_mechanic.providers.entra.token_store import EntraTokenStore


@dataclass(frozen=True)
class BrowserLaunchPlan:
    browser: str
    os_name: str
    command: str
    port: int
    user_data_dir: str
    argv: list[str]


_DEFAULT_EXECUTABLES: dict[str, dict[str, str]] = {
    "macos": {
        "edge": "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    },
    "linux": {
        "edge": "microsoft-edge",
        "chrome": "google-chrome",
    },
    "windows": {
        "edge": r"$Env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "chrome": r"$Env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    },
}

_DEFAULT_PROFILES: dict[str, dict[str, str]] = {
    "macos": {
        "edge": "/tmp/qm-edge-cdp",
        "chrome": "/tmp/qm-chrome-cdp",
    },
    "linux": {
        "edge": "/tmp/qm-edge-cdp",
        "chrome": "/tmp/qm-chrome-cdp",
    },
    "windows": {
        "edge": r"$Env:TEMP\qm-edge-cdp",
        "chrome": r"$Env:TEMP\qm-chrome-cdp",
    },
}

_MICROSOFT_COOKIE_NAMES = {
    "ESTSAUTHPERSISTENT",
    "ESTSAUTH",
    "ESTSAUTHLIGHT",
    "x-ms-RefreshTokenCredential",
    "x-ms-CredentialKey",
}
_MICROSOFT_HINT_DOMAIN_MARKERS = (
    "microsoft",
    "live.com",
    "office.com",
    "office.net",
    "azure.com",
    "windows.net",
)


def detect_os_name() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def build_launch_plan(
    *,
    browser: str,
    os_name: str | None = None,
    port: int = 9222,
    browser_path: str | None = None,
    user_data_dir: str | None = None,
) -> BrowserLaunchPlan:
    os_norm = (os_name or detect_os_name()).strip().lower()
    browser_norm = browser.strip().lower()

    if os_norm not in _DEFAULT_EXECUTABLES:
        raise ValueError(f"Unsupported OS: {os_norm}")
    if browser_norm not in _DEFAULT_EXECUTABLES[os_norm]:
        raise ValueError(f"Unsupported browser: {browser_norm}")

    executable = browser_path or _DEFAULT_EXECUTABLES[os_norm][browser_norm]
    profile_dir = user_data_dir or _DEFAULT_PROFILES[os_norm][browser_norm]
    argv = [
        executable,
        f"--remote-debugging-port={port}",
        f"--remote-allow-origins=http://127.0.0.1:{port}",
        f"--user-data-dir={profile_dir}",
    ]
    command = (
        f"{_display_executable(executable, os_norm)} --remote-debugging-port={port} "
        f"--remote-allow-origins=http://127.0.0.1:{port} "
        f"--user-data-dir={profile_dir}"
    )
    return BrowserLaunchPlan(
        browser=browser_norm,
        os_name=os_norm,
        command=command,
        port=port,
        user_data_dir=profile_dir,
        argv=argv,
    )


def launch_browser(
    *,
    browser: str,
    os_name: str | None = None,
    port: int = 9222,
    browser_path: str | None = None,
    user_data_dir: str | None = None,
) -> BrowserLaunchPlan:
    os_norm = (os_name or detect_os_name()).strip().lower()
    profile_dir = user_data_dir or tempfile.mkdtemp(prefix=f"qm-{browser}-cdp-")
    plan = build_launch_plan(
        browser=browser,
        os_name=os_norm,
        port=port,
        browser_path=browser_path,
        user_data_dir=profile_dir,
    )
    if os_norm == "windows":
        subprocess.Popen(  # noqa: S602
            plan.command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True,
        )
    else:
        subprocess.Popen(  # noqa: S603
            plan.argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return plan


def import_browser_session(
    *,
    host: str = "127.0.0.1",
    port: int = 9222,
    http: httpx.Client | Any | None = None,
) -> tuple[EntraTokenStore, dict[str, Any]]:
    """Attach to a local browser CDP endpoint and import Microsoft auth cookies."""
    owned = http is None
    client = http or httpx.Client(timeout=10)
    try:
        version = client.get(f"http://{host}:{port}/json/version").json()
        ws_url = version.get("webSocketDebuggerUrl")
        if not ws_url:
            raise ValueError("CDP endpoint did not return a webSocketDebuggerUrl")

        try:
            ws = websocket.create_connection(ws_url, timeout=10)
        except websocket.WebSocketBadStatusException as exc:
            if exc.status_code == 403:
                raise ValueError(
                    "Chrome rejected the CDP websocket origin. Relaunch the browser with "
                    f"--remote-allow-origins=http://127.0.0.1:{port} and retry."
                ) from exc
            raise ValueError(f"Browser CDP websocket handshake failed: HTTP {exc.status_code}") from exc
        except websocket.WebSocketException as exc:
            raise OSError(f"CDP websocket connection failed: {exc}") from exc
        try:
            ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies", "params": {}}))
            response = json.loads(ws.recv())
        finally:
            ws.close()

        raw_cookies = response.get("result", {}).get("cookies", [])
        if not _filter_microsoft_auth_cookies(raw_cookies):
            raw_cookies = _collect_page_target_cookies(client, host=host, port=port) or raw_cookies
        filtered = _filter_microsoft_auth_cookies(raw_cookies)
        if not filtered:
            raise ValueError(_build_no_cookie_guidance(raw_cookies))

        store = EntraTokenStore()
        for cookie in filtered:
            name = cookie.get("name", "")
            value = str(cookie.get("value", "")).strip()
            if not value:
                continue
            if name == "x-ms-RefreshTokenCredential":
                store.add_token(ingest_prt_cookie(value))
            else:
                tenant = _infer_tenant(cookie)
                store.add_token(
                    ingest_ests_cookie(
                        value,
                        tenant_id=tenant,
                        cookie_name=name,
                        cookie_domain=str(cookie.get("domain", "")) or None,
                    )
                )

        return store, {
            "browser_name": version.get("Browser"),
            "cookie_count": len(filtered),
            "host": host,
            "port": port,
        }
    except httpx.HTTPError as exc:
        raise OSError(f"Failed to reach browser CDP endpoint at http://{host}:{port}: {exc}") from exc
    finally:
        if owned:
            client.close()


def _filter_microsoft_auth_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cookie in cookies:
        name = cookie.get("name", "")
        if name not in _MICROSOFT_COOKIE_NAMES:
            continue
        out.append(cookie)
    return out


def _collect_page_target_cookies(
    client: httpx.Client | Any,
    *,
    host: str,
    port: int,
) -> list[dict[str, Any]]:
    try:
        targets = client.get(f"http://{host}:{port}/json/list").json()
    except httpx.HTTPError:
        return []
    if not isinstance(targets, list):
        return []

    collected: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        if not isinstance(target, dict):
            continue
        if not _is_real_page_target(target):
            continue
        ws_url = target.get("webSocketDebuggerUrl")
        if not ws_url:
            continue
        cookies = _get_cookies_via_target_ws(ws_url)
        for cookie in _filter_microsoft_auth_cookies(cookies):
            key = (
                str(cookie.get("name", "")),
                str(cookie.get("domain", "")),
                str(cookie.get("value", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            collected.append(cookie)
    return collected


def _is_real_page_target(target: dict[str, Any]) -> bool:
    target_type = str(target.get("type", "")).lower()
    url = str(target.get("url", "")).strip().lower()
    if target_type != "page":
        return False
    if not (url.startswith("http://") or url.startswith("https://")):
        return False
    return True


def _get_cookies_via_target_ws(ws_url: str) -> list[dict[str, Any]]:
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
    except websocket.WebSocketException:
        return []
    try:
        ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {}}))
        try:
            ws.recv()
        except Exception:
            return []
        ws.send(json.dumps({"id": 2, "method": "Network.getAllCookies", "params": {}}))
        response = json.loads(ws.recv())
    except Exception:
        return []
    finally:
        ws.close()
    return response.get("result", {}).get("cookies", [])


def _build_no_cookie_guidance(cookies: list[dict[str, Any]]) -> str:
    candidate_domains, candidate_names = _summarize_candidate_cookie_surface(cookies)
    base = (
        "No Microsoft auth cookies found in the attached browser session. "
        "Complete a real Microsoft sign-in flow in the launched temp profile "
        "(for example, https://login.microsoftonline.com/ or https://portal.azure.com/) and retry."
    )
    if not candidate_domains and not candidate_names:
        return base

    domains = ", ".join(candidate_domains) if candidate_domains else "none"
    names = ", ".join(candidate_names) if candidate_names else "none"
    accepted = ", ".join(sorted(_MICROSOFT_COOKIE_NAMES))
    return (
        f"{base} Microsoft-adjacent cookies were visible on domains: {domains}. "
        f"Names seen: {names}. Current importable cookie names: {accepted}."
    )


def _summarize_candidate_cookie_surface(
    cookies: list[dict[str, Any]],
    *,
    max_items: int = 6,
) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    names: list[str] = []
    seen_domains: set[str] = set()
    seen_names: set[str] = set()

    for cookie in cookies:
        domain = str(cookie.get("domain", "")).lstrip(".").lower()
        name = str(cookie.get("name", "")).strip()
        if not _looks_microsoft_adjacent(domain):
            continue
        if domain and domain not in seen_domains and len(domains) < max_items:
            domains.append(domain)
            seen_domains.add(domain)
        if name and name not in seen_names and len(names) < max_items:
            names.append(name)
            seen_names.add(name)

    return domains, names


def _looks_microsoft_adjacent(domain: str) -> bool:
    if not domain:
        return False
    return any(marker in domain for marker in _MICROSOFT_HINT_DOMAIN_MARKERS)


def _infer_tenant(cookie: dict[str, Any]) -> str | None:
    """Best-effort tenant inference from cookie metadata.

    For Phase 2 initial attach/import, cookies are usually opaque and tenant
    inference is weak; keep None unless something explicit is present later.
    """
    del cookie
    return None


def _display_executable(executable: str, os_name: str) -> str:
    if os_name == "windows":
        return f'& "{executable}"'
    if os_name in ("macos", "windows") and " " in executable:
        return f'"{executable}"'
    return executable
