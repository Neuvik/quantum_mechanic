# ================================================================
# MODULE: quantum_mechanic.providers.entra.auth
# ----------------------------------------------------------------
# PURPOSE:   Entra ID authentication provider.
#
#            authenticate() deserializes a stored EntraTokenStore
#            from workspace secret_data. The token store is the
#            session object (ctx.session).
#
#            whoami() calls Graph /me using the best available
#            Graph-scoped access token.
#
# DETECTION (Blue Team):
#   Azure AD Sign-in Logs: Token acquisitions from unexpected
#   client IDs, IP addresses, or device states. Non-interactive
#   sign-ins using FOCI refresh tokens show as the originating
#   app (e.g., "Microsoft Office") even when the real caller is QM.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult
from quantum_mechanic.providers.entra.token_store import (
    GRAPH,
    EntraTokenStore,
    decode_jwt_claims,
)

logger = logging.getLogger(__name__)

GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"
GRAPH_ME_ROLES_URL = "https://graph.microsoft.com/v1.0/me/memberOf"


class EntraAuthProvider(AuthProvider):
    """Entra ID (Azure AD) identity provider.

    secret_data format:
        Serialized EntraTokenStore JSON produced by
        import/acquire commands.
    """

    @property
    def provider_name(self) -> str:
        return "entra"

    def authenticate(self, secret_data: dict[str, Any]) -> EntraTokenStore:
        """Deserialize EntraTokenStore from workspace secret_data.

        Args:
            secret_data: Dict with "token_store" key containing
                serialized EntraTokenStore, or legacy flat format.

        Returns:
            EntraTokenStore ready for use as ctx.session.
        """
        if "token_store" in secret_data:
            return EntraTokenStore.from_dict(secret_data["token_store"])

        # Legacy: direct token_store dict at top level.
        if "tokens" in secret_data:
            return EntraTokenStore.from_dict(secret_data)

        # Empty store — operator will populate via import/acquire.
        logger.debug("entra: authenticate called with no token material — empty store")
        return EntraTokenStore(
            tenant_id=secret_data.get("tenant_id"),
            user_upn=secret_data.get("user_upn"),
        )

    def whoami(self, session: Any) -> WhoAmIResult:
        """Identify the Entra ID principal via Graph /me.

        Args:
            session: EntraTokenStore instance.

        Returns:
            WhoAmIResult with Entra identity information.

        Raises:
            ValueError: If no valid Graph token is available.
        """
        store: EntraTokenStore = session
        token = store.best_token(GRAPH)

        if token is None:
            raise ValueError(
                "No valid Graph token available. "
                "Run: import entra browserdump <path>  or  acquire entra device_code"
            )

        # If the best token is a refresh token (FOCI), expand to access token first.
        if token.token_type == "refresh_token":
            from quantum_mechanic.providers.entra.foci import foci_expand
            access = foci_expand(store, GRAPH)
            if access is None:
                raise ValueError("FOCI expansion for Graph failed. Check refresh token validity.")
            token = access

        headers = {
            "Authorization": f"Bearer {token.value}",
            "Content-Type": "application/json",
        }

        with httpx.Client(timeout=30) as http:
            resp = http.get(GRAPH_ME_URL, headers=headers)

        if resp.status_code == 401:
            error_body = resp.json()
            error_code = error_body.get("error", {}).get("code", "")
            guidance = store.cap_guidance(error_code)
            if guidance:
                raise ValueError(guidance)
            raise ValueError(f"Graph /me returned 401: {error_body}")

        resp.raise_for_status()
        me = resp.json()

        # Decode roles from token claims — Graph /me/memberOf is a separate
        # call; use claim data for whoami to keep it fast.
        claims = token.raw_claims or decode_jwt_claims(token.value)
        roles: list[str] = claims.get("roles", [])
        wids: list[str] = claims.get("wids", [])

        principal_id = me.get("id", claims.get("oid", "unknown"))
        upn = me.get("userPrincipalName") or store.user_upn or claims.get("upn", "")
        display_name = me.get("displayName", upn)
        tenant_id = me.get("tenantId") or store.tenant_id or claims.get("tid", "")

        # Sync back any claims we may not have had.
        if upn and not store.user_upn:
            store.user_upn = upn
        if tenant_id and not store.tenant_id:
            store.tenant_id = tenant_id

        return WhoAmIResult(
            provider="entra",
            principal_id=principal_id,
            principal_type="user" if upn else "service_principal",
            friendly_name=upn or display_name,
            account_id=tenant_id,
            account_name=me.get("companyName"),
            tenant_id=tenant_id,
            extra={
                "display_name": display_name,
                "mail": me.get("mail"),
                "job_title": me.get("jobTitle"),
                "department": me.get("department"),
                "mfa_registered": _mfa_registered(claims),
                "device_claims": token.device_claims,
                "foci_token": token.foci,
                "roles": roles,
                "wids": wids,
                "token_expires": (
                    token.expires_at.isoformat() if token.expires_at else None
                ),
            },
            raw_response=me,
        )


def _mfa_registered(claims: dict[str, Any]) -> bool | None:
    """Detect MFA registration from token claims."""
    amr: list[str] = claims.get("amr", [])
    if "mfa" in amr or "ngcmfa" in amr:
        return True
    if amr:
        return False
    return None
