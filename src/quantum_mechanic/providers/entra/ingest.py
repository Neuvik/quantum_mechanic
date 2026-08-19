# ================================================================
# MODULE: quantum_mechanic.providers.entra.ingest
# ----------------------------------------------------------------
# PURPOSE:   Parse and classify all token material that arrives in
#            QM — browserdump JSON, .roadtools_auth files, raw JWTs,
#            ESTS cookies, and raw PRT + session key pairs.
#
#            Returns populated EntraTokenStore instances ready for
#            persistence. Does NOT perform network exchanges — see
#            exchange.py for the ESTS/FOCI exchange layer.
# ================================================================

from __future__ import annotations

import json
import logging
from datetime import UTC
from pathlib import Path
from typing import Any

from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS
from quantum_mechanic.providers.entra.token_store import (
    ESTS_COOKIE,
    GRAPH,
    OAUTH_REFRESH,
    PRT_COOKIE,
    PRT_WITH_KEY,
    EntraToken,
    EntraTokenStore,
    decode_jwt_claims,
    token_from_jwt,
)

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Cookie name → (token_type, is_jwt) classification table.
# Mirrors capcom/browserdump entraTokenRules.
# ----------------------------------------------------------------
_COOKIE_RULES: dict[str, tuple[str, bool]] = {
    "ESTSAUTHPERSISTENT": ("ests_cookie", False),
    "ESTSAUTH": ("ests_cookie", False),
    "ESTSAUTHLIGHT": ("ests_cookie", False),
    "x-ms-RefreshTokenCredential": ("prt_cookie", True),
    "x-ms-CredentialKey": ("ests_cookie", False),
}


# ----------------------------------------------------------------
# browserdump JSON ingestion
# ----------------------------------------------------------------


def ingest_browserdump(path: str | Path) -> list[EntraTokenStore]:
    """Parse browserdump JSON output into a list of EntraTokenStores.

    One store is produced per Edge profile found in the dump.
    Handles both flat (single-profile) and nested (multi-profile)
    structures.

    Time-sensitive tokens (PRT cookies) are flagged — the caller is
    responsible for triggering immediate exchange.

    Returns:
        List of (store, needs_exchange) pairs via IngestResult.
    """
    raw = Path(path).read_text()
    data: dict[str, Any] = json.loads(raw)

    # Support two output shapes from browserdump:
    #   { "profiles": [ { ... }, ... ] }   ← multi-profile
    #   { "tokens": [...], "tenant": ... } ← single-profile flat
    if "profiles" in data:
        profiles = data["profiles"]
    else:
        profiles = [data]

    stores: list[EntraTokenStore] = []
    for profile_data in profiles:
        store = _parse_profile(profile_data)
        if store is not None:
            stores.append(store)

    return stores


def _parse_profile(data: dict[str, Any]) -> EntraTokenStore | None:
    """Parse one browserdump profile dict into an EntraTokenStore."""
    tenant = data.get("tenant") or data.get("tenant_id") or data.get("tenantId")
    profile_name = (
        data.get("profile") or data.get("profile_name") or data.get("profileName") or "Default"
    )

    store = EntraTokenStore(tenant_id=tenant)

    tokens_raw: list[dict[str, Any]] = (
        data.get("tokens")
        if isinstance(data.get("tokens"), list)
        else _flatten_token_dict(data.get("tokens", {}))
    )

    for entry in tokens_raw:
        tok = _parse_token_entry(entry, store)
        if tok is not None:
            store.add_token(tok)

    # Try to infer tenant from any JWT claims if not already set.
    if not store.tenant_id:
        for tok in store.tokens:
            if tok.tenant_id:
                store.tenant_id = tok.tenant_id
                break

    if not store.tokens:
        logger.debug("browserdump: profile %s had no recognised tokens", profile_name)
        return None

    return store


def _flatten_token_dict(d: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert { "prt_cookie": "eyJ...", ... } to list form."""
    result = []
    for key, value in d.items():
        if isinstance(value, str) and value:
            result.append({"name": key, "value": value})
    return result


def _parse_token_entry(
    entry: dict[str, Any],
    store: EntraTokenStore,
) -> EntraToken | None:
    """Classify and build an EntraToken from a single browserdump entry."""
    name = entry.get("name", "")
    value = entry.get("value", "").strip()
    if not value:
        return None

    # Explicit type field takes precedence.
    explicit_type = entry.get("type", "")
    if explicit_type == "prt_cookie":
        return ingest_prt_cookie(value)
    if explicit_type in ("ests_persistent", "ests_cookie"):
        tenant = entry.get("tenant") or store.tenant_id
        return ingest_ests_cookie(value, tenant_id=tenant)

    # Fall back to cookie-name classification table.
    rule = _COOKIE_RULES.get(name)
    if rule is None:
        return None

    token_type, is_jwt = rule

    if name == "x-ms-RefreshTokenCredential":
        return ingest_prt_cookie(value)

    if name == "x-ms-CredentialKey":
        # Session key material — store as raw for later prt_key import.
        return EntraToken(
            token_type=ESTS_COOKIE,
            value=value,
            resource="",
            tenant_id=store.tenant_id,
            raw_claims={"browserdump_name": name},
        )

    # ESTS cookies — opaque values, not JWTs.
    tenant = entry.get("tenant") or store.tenant_id
    return ingest_ests_cookie(value, tenant_id=tenant)


# ----------------------------------------------------------------
# Individual token ingest functions
# ----------------------------------------------------------------


def ingest_prt_cookie(jwt: str) -> EntraToken:
    """Build an EntraToken from an x-ms-RefreshTokenCredential JWT.

    The PRT cookie is a nonce-bound JWT with ~5 minute lifetime.
    Decoded claims are stored for operator visibility. The caller
    must trigger exchange immediately.
    """
    claims = decode_jwt_claims(jwt)
    # PRT cookies use "exp" for nonce expiry.
    from datetime import datetime

    expires_at = None
    if "exp" in claims:
        try:
            expires_at = datetime.fromtimestamp(claims["exp"], tz=UTC)
        except (ValueError, OSError):
            pass

    return EntraToken(
        token_type=PRT_COOKIE,
        value=jwt,
        resource="",
        tenant_id=claims.get("tid"),
        device_claims=True,  # PRT cookies always carry device claims
        expires_at=expires_at,
        raw_claims=claims,
    )


def ingest_ests_cookie(
    value: str,
    *,
    tenant_id: str | None = None,
    cookie_name: str | None = None,
    cookie_domain: str | None = None,
) -> EntraToken:
    """Build an EntraToken from an ESTS cookie value (opaque, not JWT)."""
    raw_claims: dict[str, Any] = {}
    if cookie_name:
        raw_claims["cookie_name"] = cookie_name
    if cookie_domain:
        raw_claims["cookie_domain"] = cookie_domain
    return EntraToken(
        token_type=ESTS_COOKIE,
        value=value,
        resource="",
        tenant_id=tenant_id,
        device_claims=False,
        raw_claims=raw_claims,
    )


def ingest_access_token(jwt: str, resource: str = GRAPH) -> EntraToken:
    """Build an EntraToken from a raw access token JWT."""
    return token_from_jwt(jwt, "access_token", resource=resource)


def ingest_refresh_token(
    token: str,
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
) -> EntraToken:
    """Build an EntraToken from a raw refresh token string.

    Refresh tokens are opaque — we can't decode claims. tenant_id
    and client_id must be supplied by the caller.
    """
    is_foci = client_id in FOCI_CLIENT_IDS if client_id else False
    return EntraToken(
        token_type=OAUTH_REFRESH,
        value=token,
        resource="",
        tenant_id=tenant_id,
        client_id=client_id,
        foci=is_foci,
    )


def ingest_prt_key(
    prt_value: str,
    session_key: str,
    *,
    tenant_id: str,
) -> EntraToken:
    """Store a raw PRT + session key pair.

    The session key lets QM mint fresh PRT cookies on demand.
    No expiry pressure — PRTs are 14-day credentials.
    """
    return EntraToken(
        token_type=PRT_WITH_KEY,
        value=prt_value,
        resource="",
        tenant_id=tenant_id,
        device_claims=True,
        raw_claims={
            "session_key": session_key,
            "tenant_id": tenant_id,
        },
    )


# ----------------------------------------------------------------
# .roadtools_auth ingestion
# ----------------------------------------------------------------


def ingest_roadtools(path: str | Path) -> EntraTokenStore:
    """Parse a .roadtools_auth JSON file into an EntraTokenStore.

    roadtools_auth format:
        {
            "_clientId": "...",
            "_resource": "https://graph.microsoft.com",
            "accessToken": "eyJ...",
            "refreshToken": "0.AS4...",
            "tenantId": "...",
            "userId": "...",
            "isMRRT": true,
            ...
        }
    """
    raw = Path(path).read_text()
    data: dict[str, Any] = json.loads(raw)

    tenant_id = data.get("tenantId") or data.get("tenant_id")
    user_upn = data.get("userId") or data.get("user_upn")
    client_id = data.get("_clientId")
    resource = data.get("_resource", GRAPH)
    is_mrrt = data.get("isMRRT", False)

    store = EntraTokenStore(tenant_id=tenant_id, user_upn=user_upn)

    if data.get("accessToken"):
        tok = token_from_jwt(
            data["accessToken"],
            "access_token",
            resource=resource,
            client_id=client_id,
        )
        # roadtools may not have expiry in the same field — try expiresOn.
        if not tok.expires_at and data.get("expiresOn"):
            from datetime import datetime

            try:
                tok.expires_at = datetime.strptime(data["expiresOn"], "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=UTC
                )
            except ValueError:
                pass
        store.add_token(tok)

    if data.get("refreshToken"):
        is_foci = bool(is_mrrt) or (client_id in FOCI_CLIENT_IDS if client_id else False)
        rt = EntraToken(
            token_type=OAUTH_REFRESH,
            value=data["refreshToken"],
            resource=resource,
            tenant_id=tenant_id,
            client_id=client_id,
            foci=is_foci,
        )
        store.add_token(rt)

    return store
