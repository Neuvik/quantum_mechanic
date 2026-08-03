# ================================================================
# MODULE: quantum_mechanic.providers.entra.scope_exchange
# ----------------------------------------------------------------
# PURPOSE:   Scope-aware FOCI expansion. Attempts to acquire a token
#            that carries a SPECIFIC Graph permission (e.g.
#            "User.Read.All") rather than the resource `.default`
#            scope set the store already has consent for.
#
#            Walks the FOCI family clients requesting the specific
#            scope. Reports back honestly with three terminal outcomes:
#
#              granted           - Token acquired and added to store
#              consent_required  - No FOCI client has consent for this
#                                  scope on this tenant (admin-consent
#                                  situation — OAuth cannot escalate)
#              invalid_grant     - RT expired/revoked/CA-blocked; retry
#                                  will fail until a fresh acquire
#              unknown           - Some other AAD error; error text
#                                  preserved for the caller
#
#            The C2 auto-retry flow in the runner consumes this — see
#            core/runner.py::_maybe_scope_retry.
# ================================================================

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any

import httpx

from quantum_mechanic.providers.entra.foci import (
    FOCI_CLIENT_IDS,
    FOCI_DEFAULT_CLIENT,
    RESOURCE_CLIENT_HINTS,
    TOKEN_ENDPOINT,
)
from quantum_mechanic.providers.entra.token_store import (
    GRAPH,
    EntraToken,
    EntraTokenStore,
    token_from_jwt,
)

logger = logging.getLogger(__name__)


# AAD error codes that mean "no admin/user consent exists for this scope on
# any client we tried" — no amount of retry against other FOCI clients will
# help. The operator needs admin consent or a different client entirely.
_CONSENT_ERROR_CODES = {"consent_required", "interaction_required"}

# AAD error codes that mean "the RT itself is dead" — again, retrying scopes
# won't help; the operator needs to re-authenticate.
_INVALID_GRANT_CODES = {"invalid_grant", "invalid_client"}


@dataclass
class ScopeExchangeResult:
    """Outcome of a scope-aware FOCI expansion attempt.

    Fields:
        status:         One of "granted", "consent_required", "invalid_grant",
                        "no_rt", "unknown".
        token:          The acquired EntraToken when status="granted"; else None.
        tried_clients:  Ordered list of (client_id, friendly_name) attempted.
        last_error:     Human-readable last error, useful for diagnostics.
    """
    status: str
    token: EntraToken | None = None
    tried_clients: list[tuple[str, str]] = field(default_factory=list)
    last_error: str = ""


def _v2_scope(resource: str, permission: str) -> str:
    """Compose an OAuth v2 scope string like
    'https://graph.microsoft.com/User.Read.All openid offline_access'.

    Callers pass just the permission name (e.g. 'User.Read.All'); this
    prepends the resource so we hit the v2 endpoint's per-permission grant
    path rather than the `.default` bulk path that only re-issues already-
    consented scopes.
    """
    resource_root = resource.rstrip("/")
    return f"{resource_root}/{permission} openid offline_access"


def _classify_error(code: str) -> str | None:
    """Map an AAD error code to a ScopeExchangeResult.status, or None if
    the error is transient/retryable against a different FOCI client."""
    if code in _CONSENT_ERROR_CODES:
        return "consent_required"
    if code in _INVALID_GRANT_CODES:
        return "invalid_grant"
    return None


def try_acquire_scope(
    store: EntraTokenStore,
    required_scope: str,
    resource: str = GRAPH,
    http: httpx.Client | None = None,
) -> ScopeExchangeResult:
    """Attempt to acquire a token carrying `required_scope` (e.g.
    "User.Read.All") on `resource` via FOCI family clients.

    Iterates the FOCI clients in resource-hinted-first order, requesting
    the specific v2 scope. Stops at the first grant. Classifies the final
    error state honestly so the caller can decide whether to retry, prompt
    the operator, or emit a diagnostic hint.

    Args:
        store:          The active EntraTokenStore (must contain a FOCI RT).
        required_scope: Graph permission name only (e.g. "User.Read.All"),
                        without the resource prefix or offline_access marker.
        resource:       The target resource root (default: Microsoft Graph).
        http:           Optional httpx.Client to reuse; a fresh one is made
                        and closed automatically if omitted.

    Returns:
        ScopeExchangeResult — see class docstring.
    """
    refresh = store.foci_refresh_token()
    if refresh is None:
        return ScopeExchangeResult(
            status="no_rt",
            last_error="Active store has no FOCI refresh token.",
        )

    tenant = store.tenant_id or refresh.tenant_id or "common"
    url = TOKEN_ENDPOINT.format(tenant=tenant)

    hint = RESOURCE_CLIENT_HINTS.get(resource.rstrip("/"), FOCI_DEFAULT_CLIENT)
    fallbacks = [c for c in FOCI_CLIENT_IDS if c != hint]
    random.shuffle(fallbacks)
    clients_to_try = [hint] + fallbacks

    scope = _v2_scope(resource, required_scope)
    owned = http is None
    client = http or httpx.Client(timeout=30)
    tried: list[tuple[str, str]] = []
    last_error = ""
    terminal_status: str | None = None

    try:
        for client_id in clients_to_try:
            friendly = FOCI_CLIENT_IDS.get(client_id, "unknown")
            tried.append((client_id, friendly))
            try:
                resp = client.post(
                    url,
                    data={
                        "grant_type": "refresh_token",
                        "client_id": client_id,
                        "refresh_token": refresh.value,
                        "scope": scope,
                    },
                )
            except httpx.HTTPError as e:
                last_error = f"HTTP transport error: {e}"
                logger.debug("try_acquire_scope: transport error on %s: %s", client_id, e)
                continue

            if resp.status_code == 429:
                last_error = "AAD throttling (HTTP 429)"
                continue

            try:
                data: dict[str, Any] = resp.json()
            except ValueError:
                last_error = f"Non-JSON response (HTTP {resp.status_code}): {resp.text[:120]}"
                continue

            if "error" in data:
                code = str(data.get("error", "")).strip()
                desc = str(data.get("error_description", "")).strip() or code
                last_error = f"{code}: {desc}"
                classified = _classify_error(code)
                if classified is not None:
                    # Terminal error — no other FOCI client will help. Record
                    # the classification and stop trying.
                    terminal_status = classified
                    break
                # Otherwise this client just doesn't have the scope; try next.
                continue

            access_jwt = data.get("access_token", "")
            if not access_jwt:
                last_error = "Response missing access_token."
                continue

            token = token_from_jwt(
                access_jwt,
                token_type="access_token",
                resource=resource,
                client_id=client_id,
            )
            store.add_token(token)

            # Persist any updated RT the server returned.
            if "refresh_token" in data:
                new_rt = token_from_jwt(
                    data["refresh_token"],
                    token_type="refresh_token",
                    resource=resource,
                    client_id=client_id,
                )
                store.add_token(new_rt)

            return ScopeExchangeResult(
                status="granted",
                token=token,
                tried_clients=tried,
                last_error="",
            )
    finally:
        if owned:
            client.close()

    return ScopeExchangeResult(
        status=terminal_status or "unknown",
        tried_clients=tried,
        last_error=last_error,
    )
