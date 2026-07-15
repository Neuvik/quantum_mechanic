# ================================================================
# MODULE: quantum_mechanic.providers.entra.graph
# ----------------------------------------------------------------
# PURPOSE:   Thin Graph API helpers shared across entra techniques.
#
#            graph_list() handles paginated GET requests — Graph
#            returns up to $top items per page, with @odata.nextLink
#            pointing to the next page.
# ================================================================

from __future__ import annotations

import email.utils
import logging
import random
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from quantum_mechanic.providers.entra.token_store import decode_jwt_claims

logger = logging.getLogger(__name__)


# ================================================================
# TYPED EXCEPTIONS for honest error reporting.
#
# graph_list() previously swallowed 4xx/5xx responses and returned
# an empty list, making techniques look successful when they were
# actually denied. These exceptions let techniques catch the failure
# and return status="denied" so operators see a red ✗ and the
# required Graph scope.
# ================================================================


class GraphError(Exception):
    """Base class for Graph API failures worth reporting to the operator."""

    def __init__(
        self,
        url: str,
        status: int,
        code: str = "Unknown",
        message: str = "",
        scope_hint: str | None = None,
    ) -> None:
        self.url = url
        self.status = status
        self.code = code
        self.message = message
        self.scope_hint = scope_hint
        super().__init__(f"HTTP {status} on {url}: {code} — {message}")


class GraphAccessError(GraphError):
    """4xx failure — the token is missing scope or the caller is not authorized."""


class GraphTransientError(GraphError):
    """5xx failure or exhausted retry budget — service-side problem."""


# Scope-hint map: URL path prefix (longest first) → required Graph permission name.
# Consulted when raising GraphAccessError so operators get an actionable hint
# instead of an opaque 403. New entries added under A8.
_SCOPE_HINTS: list[tuple[str, str]] = [
    ("/identityGovernance/entitlementManagement/accessPackages", "EntitlementManagement.Read.All"),
    ("/identityGovernance/entitlementManagement", "EntitlementManagement.Read.All"),
    ("/roleManagement/directory/roleAssignments", "RoleManagement.Read.Directory"),
    ("/roleManagement/directory", "RoleManagement.Read.Directory"),
    ("/deviceManagement/roleAssignments", "DeviceManagementRBAC.Read.All"),
    ("/deviceManagement", "DeviceManagementConfiguration.Read.All"),
    ("/security/roleAssignments", "SecurityIdentitiesSensors.Read.All"),
    ("/security", "SecurityEvents.Read.All"),
    ("/identity/conditionalAccess/policies", "Policy.Read.ConditionalAccess"),
    ("/identity/conditionalAccess", "Policy.Read.All"),
    ("/applications", "Application.Read.All"),
    ("/servicePrincipals", "Application.Read.All"),
    ("/devices", "Device.Read.All"),
    ("/groups", "Group.Read.All"),
    ("/users", "User.Read.All"),
]


def _lookup_scope_hint(url: str) -> str | None:
    """Return the required Graph permission for a URL, or None if unknown."""
    for prefix, scope in _SCOPE_HINTS:
        if prefix in url:
            return scope
    return None


def graph_error_to_result(e: GraphError, **extra: Any) -> dict[str, Any]:
    """Convert a raised GraphError into the standard technique result shape.

    Used by all Entra techniques that call graph_list() so the runner sees
    a consistent status="denied" or status="error" and can render the red ✗
    glyph plus the required scope hint.
    """
    status = "denied" if isinstance(e, GraphAccessError) else "error"
    return {
        "status": status,
        "error": f"HTTP {e.status} on {e.url}: {e.code} — {e.message}",
        "http_status": e.status,
        "error_code": e.code,
        "required_scope": e.scope_hint,
        **extra,
    }


def _parse_error_body(resp: httpx.Response) -> tuple[str, str]:
    """Extract (code, message) from a Graph error response body.

    Graph errors look like {"error": {"code": "X", "message": "Y"}}. When the
    body is not JSON (HTML gateway rejection, empty response), fall back to
    sentinel values so callers can still report *something*.
    """
    try:
        body = resp.json()
    except (ValueError, Exception):
        return "Unknown", (resp.text or "")[:200]
    if isinstance(body, dict):
        err = body.get("error", {}) if isinstance(body.get("error"), dict) else {}
        return err.get("code", "Unknown"), err.get("message", "")
    return "Unknown", ""

def parse_retry_after(value: str) -> float:
    """Parse Retry-After header (seconds or HTTP-date)."""
    if not value:
        return 0.0
    try:
        return float(value)
    except ValueError:
        try:
            dt = email.utils.parsedate_to_datetime(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            now = datetime.now(UTC)
            return max(0.0, (dt - now).total_seconds())
        except Exception:
            return 0.0

def _get_client_id(headers: dict[str, str]) -> str:
    """Extract client ID from Authorization header if possible."""
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        claims = decode_jwt_claims(token)
        return claims.get("appid") or claims.get("azp") or "unknown"
    return "unknown"

def _graph_call(
    http: httpx.Client,
    method: str,
    url: str,
    headers: dict[str, str],
    json_data: dict[str, Any] | None = None,
    max_retries: int = 3
) -> httpx.Response:
    """Execute a Graph API call with jittered exponential backoff for 429/5xx."""

    # Check for token corruption (non-ASCII characters)
    auth = headers.get("Authorization", "")
    if any(ord(c) < 32 or ord(c) > 126 for c in auth):
        logger.critical(
            "TOKEN CORRUPTION DETECTED: Authorization header contains non-ASCII "
            "characters. This will cause 401 Unauthorized errors."
        )

    retry_delay = 2.0

    for attempt in range(1, max_retries + 1):
        resp = http.request(method, url, headers=headers, json=json_data)

        # 1. Handle Throttling (429) or Server Error (5xx)
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == max_retries:
                return resp

            # Respect Retry-After header if provided
            wait_time = parse_retry_after(resp.headers.get("Retry-After", ""))
            if wait_time <= 0:
                wait_time = retry_delay

            # Add jitter
            wait_time *= random.uniform(0.5, 1.5)

            client_id = _get_client_id(headers)
            logger.warning(
                "Graph API throttled (HTTP %d) for client %s. Waiting %.1fs (Attempt %d/%d)",
                resp.status_code, client_id, wait_time, attempt, max_retries
            )
            time.sleep(wait_time)
            retry_delay *= 2 # Exponential backoff
            continue

        return resp

    # Should not be reachable due to the return in the loop
    return resp

def graph_list(
    http: httpx.Client,
    url: str,
    headers: dict[str, str],
    max_pages: int = 20,
) -> list[dict[str, Any]]:
    """Fetch all pages of a Graph list endpoint.

    Args:
        http:      Caller-managed httpx.Client.
        url:       Initial Graph URL (may include $top, $select, $filter).
        headers:   Auth headers (Authorization: Bearer ...).
        max_pages: Safety cap on pages fetched (default 20 × $top items).

    Returns:
        Flat list of all items from the "value" array across all pages.
    """
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    pages = 0

    while next_url and pages < max_pages:
        resp = _graph_call(http, "GET", next_url, headers=headers)

        if resp.status_code != 200:
            # First-page failure: raise so the technique reports status="denied"
            # or status="error" instead of silently returning an empty list.
            # Later-page failure: return the partial results we already have
            # (best-effort — the operator got *some* data).
            if pages == 0:
                code, message = _parse_error_body(resp)
                scope_hint = _lookup_scope_hint(next_url)
                if 400 <= resp.status_code < 500:
                    raise GraphAccessError(
                        url=next_url,
                        status=resp.status_code,
                        code=code,
                        message=message,
                        scope_hint=scope_hint,
                    )
                raise GraphTransientError(
                    url=next_url,
                    status=resp.status_code,
                    code=code,
                    message=message,
                    scope_hint=scope_hint,
                )
            logger.warning(
                "Graph list partial failure at page %d of %s (HTTP %d): %s",
                pages, next_url, resp.status_code, resp.text[:200],
            )
            break

        body = resp.json()
        items.extend(body.get("value", []))
        next_url = body.get("@odata.nextLink")
        pages += 1

    return items
