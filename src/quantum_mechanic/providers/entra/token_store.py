# ================================================================
# MODULE: quantum_mechanic.providers.entra.token_store
# ----------------------------------------------------------------
# PURPOSE:   EntraTokenStore — canonical session object for the
#            entra provider. Holds all token material (PRT cookies,
#            ESTS cookies, refresh tokens, access tokens, raw PRT +
#            session key pairs), tracks device state, and exposes
#            FOCI-aware token selection.
#
#            ctx.session is always an EntraTokenStore instance when
#            the active provider is "entra". Techniques call
#            ctx.session.best_token(resource) — never manage tokens
#            directly.
# ================================================================

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Known Microsoft resource URIs.
# ----------------------------------------------------------------
GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"
EXCHANGE = "https://outlook.office.com"
SUBSTRATE = "https://substrate.office.com"
VAULT = "https://vault.azure.net"
STORAGE = "https://storage.azure.com"
SQL = "https://database.windows.net"

# ----------------------------------------------------------------
# AADSTS error codes that indicate CAP policy blocks.
# ----------------------------------------------------------------
CAP_ERRORS: dict[str, str] = {
    "AADSTS53003": (
        "Conditional Access policy requires a compliant device.\n"
        "  Options:\n"
        "  1. acquire entra device_enroll  (satisfies Joined Device, not Compliant)\n"
        "  2. Use BrowserCore path on a physically compliant device (browserdump --prt)\n"
        "  3. If Intune MDM is not enforced: device_enroll may satisfy this policy"
    ),
    "AADSTS53000": (
        "Conditional Access policy requires a joined device.\n"
        "  Options:\n"
        "  1. acquire entra device_enroll  (virtual enrollment satisfies Joined Device CAP)\n"
        "  2. Import a PRT cookie from a joined device (browserdump --prt)"
    ),
    "AADSTS50076": (
        "MFA is required for this resource.\n"
        "  Options:\n"
        "  1. acquire entra device_code  (victim completes MFA interactively)\n"
        "  2. acquire entra interactive  (operator completes MFA in browser)\n"
        "  3. If token already has MFA claim: try a different resource scope"
    ),
}


# ----------------------------------------------------------------
# EntraToken.token_type values — OAuth2/Entra spec vocabulary, not
# secrets. Named here so comparisons don't repeat the literal string
# at every call site (and so a variable/constant named "token_*"
# assigned a plain string doesn't read as a hardcoded credential).
# ----------------------------------------------------------------
OAUTH_ACCESS = "access_token"
OAUTH_REFRESH = "refresh_token"
PRT_WITH_KEY = "prt_with_key"
PRT_COOKIE = "prt_cookie"
ESTS_COOKIE = "ests_cookie"


@dataclass
class EntraToken:
    """A single token artifact — access token, refresh token, cookie, or raw PRT."""

    token_type: str
    # "access_token" | "refresh_token" | "prt_cookie" | "ests_cookie"
    # | "prt_with_key" | "device_cert"
    value: str
    resource: str  # target resource URI; empty for PRT material
    tenant_id: str | None = None
    client_id: str | None = None
    expires_at: datetime | None = None
    device_claims: bool = False  # True if token carries deviceid / join_type claims
    foci: bool = False  # True if this refresh token is a FOCI family member
    scopes: list[str] = field(default_factory=list)
    raw_claims: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.value:
            self.value = self.value.strip()

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at

    @property
    def minutes_remaining(self) -> float | None:
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(UTC)
        return delta.total_seconds() / 60


@dataclass
class EntraDeviceState:
    """Virtual or physical device enrolled against Entra ID."""

    device_id: str
    device_cert_pem: str
    transport_key_pem: str  # RSA private key used to sign PRT requests
    tenant_id: str
    enrolled_at: datetime
    join_type: str  # "azureADJoined" | "hybridAzureADJoined"


@dataclass
class EntraTokenStore:
    """Session object for the entra provider.

    Holds all token material for a tenant session. Techniques
    call best_token(resource) — the store handles FOCI expansion
    transparently and surfaces CAP guidance on failure.
    """

    tenant_id: str | None = None
    user_upn: str | None = None
    tokens: list[EntraToken] = field(default_factory=list)
    device: EntraDeviceState | None = None
    _dirty: bool = field(default=False, repr=False, init=False)

    # ----------------------------------------------------------------
    # Token selection
    # ----------------------------------------------------------------

    def best_token(self, resource: str) -> EntraToken | None:
        """Return the most capable non-expired token for the resource.

        Selection order:
        1. Non-expired access token scoped directly to the resource
        2. FOCI refresh token (caller must exchange it — returned as-is
           so the acquisition layer can perform the exchange and cache it)
        """
        direct = self._valid_access_token(resource)
        if direct:
            return direct
        foci = self.foci_refresh_token()
        if foci:
            return foci
        return None

    def _valid_access_token(self, resource: str) -> EntraToken | None:
        for tok in self.tokens:
            if (
                tok.token_type == OAUTH_ACCESS
                and not tok.is_expired
                and _resource_matches(tok.resource, resource)
            ):
                return tok
        return None

    def foci_refresh_token(self) -> EntraToken | None:
        """Return the first valid FOCI refresh token."""
        for tok in self.tokens:
            if tok.token_type == OAUTH_REFRESH and tok.foci and not tok.is_expired:
                return tok
        return None

    def refresh_token(self, resource: str | None = None) -> EntraToken | None:
        """Return the best refresh token, optionally scoped to a resource."""
        for tok in self.tokens:
            if tok.token_type == OAUTH_REFRESH and not tok.is_expired:
                if resource is None or _resource_matches(tok.resource, resource):
                    return tok
        return None

    def prt_material(self) -> EntraToken | None:
        """Return stored raw PRT + session key material if present."""
        for tok in self.tokens:
            if tok.token_type == PRT_WITH_KEY:
                return tok
        return None

    def prt_cookie(self) -> EntraToken | None:
        """Return the most recent PRT cookie (x-ms-RefreshTokenCredential)."""
        for tok in self.tokens:
            if tok.token_type == PRT_COOKIE and not tok.is_expired:
                return tok
        return None

    # ----------------------------------------------------------------
    # State queries
    # ----------------------------------------------------------------

    def has_device_claims(self) -> bool:
        """True if any stored token carries device join claims."""
        return any(tok.device_claims for tok in self.tokens)

    def can_satisfy_joined_device_cap(self) -> bool:
        """True if device enrollment exists or a device-claim token is stored."""
        return self.device is not None or self.has_device_claims()

    def token_summary(self) -> str:
        """Return a compact label of which token types are present, e.g. 'PRT FOCI ARM Graph'."""
        labels: list[str] = []
        for tok in self.tokens:
            if tok.is_expired:
                continue
            if tok.token_type == PRT_WITH_KEY:
                labels.append("PRT")
            elif tok.token_type == PRT_COOKIE:
                labels.append("PRTcookie")
            elif tok.token_type == OAUTH_REFRESH and tok.foci:
                labels.append("FOCI")
            elif tok.token_type == OAUTH_REFRESH:
                labels.append("RT")
            elif tok.token_type == OAUTH_ACCESS:
                if "management.azure.com" in tok.resource:
                    labels.append("ARM")
                elif "graph.microsoft.com" in tok.resource:
                    labels.append("Graph")
                elif "sharepoint.com" in tok.resource:
                    labels.append("SPO")
                else:
                    labels.append("AT")
        seen: list[str] = []
        for label in labels:
            if label not in seen:
                seen.append(label)
        return " ".join(seen) if seen else "no valid tokens"

    def token_details(self) -> list[dict[str, Any]]:
        """Return per-token structured detail for the shell display.

        Each entry: {kind, resource, expires_at, minutes_remaining, client_id,
        foci, scopes, roles}. Shell formatters render this — the store does
        not format strings itself. Expired tokens ARE included so operators
        see why an old token stopped working.
        """
        out: list[dict[str, Any]] = []
        for tok in self.tokens:
            claims = decode_jwt_claims(tok.value) if tok.token_type == OAUTH_ACCESS else {}
            # scp = delegated (space-separated), roles = application (list)
            scp = claims.get("scp") or ""
            scopes = scp.split() if isinstance(scp, str) else []
            roles = claims.get("roles") or []
            if isinstance(roles, str):
                roles = [roles]

            if tok.token_type == PRT_WITH_KEY:
                kind = "PRT"
            elif tok.token_type == PRT_COOKIE:
                kind = "PRTcookie"
            elif tok.token_type == OAUTH_REFRESH:
                kind = "FOCI RT" if tok.foci else "RT"
            elif tok.token_type == OAUTH_ACCESS:
                if "management.azure.com" in (tok.resource or ""):
                    kind = "ARM AT"
                elif "graph.microsoft.com" in (tok.resource or ""):
                    kind = "Graph AT"
                elif "sharepoint.com" in (tok.resource or ""):
                    kind = "SPO AT"
                else:
                    kind = "AT"
            else:
                kind = tok.token_type

            out.append(
                {
                    "kind": kind,
                    "resource": tok.resource or "",
                    "token_type": tok.token_type,
                    "foci": bool(tok.foci),
                    "client_id": tok.client_id or "",
                    "expires_at": tok.expires_at.isoformat() if tok.expires_at else None,
                    "minutes_remaining": tok.minutes_remaining,
                    "is_expired": tok.is_expired,
                    "scopes": scopes,
                    "roles": list(roles),
                }
            )
        return out

    def add_token(self, token: EntraToken) -> None:
        """Add or replace a token.

        Most token types deduplicate by token_type + resource.
        ESTS cookies keep distinct browser cookie variants (persistent/light/etc.)
        by including cookie_name in the deduplication key.
        """
        cookie_name = None
        if token.token_type == ESTS_COOKIE:
            cookie_name = token.raw_claims.get("cookie_name")
        self.tokens = [
            t
            for t in self.tokens
            if not (
                t.token_type == token.token_type
                and t.resource == token.resource
                and (
                    token.token_type != ESTS_COOKIE
                    or t.raw_claims.get("cookie_name") == cookie_name
                )
            )
        ]
        self.tokens.append(token)
        self._dirty = True

    # ----------------------------------------------------------------
    # roadtools interop
    # ----------------------------------------------------------------

    def export_roadtools_auth(self, resource: str = GRAPH) -> dict[str, Any]:
        """Serialize to .roadtools_auth JSON format for roadrecon interop."""
        access = self._valid_access_token(resource)
        refresh = self.refresh_token(resource) or self.foci_refresh_token()

        if not access and not refresh:
            raise ValueError(f"No token available for resource: {resource}")

        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Office (FOCI default)
        if access and access.client_id:
            client_id = access.client_id
        elif refresh and refresh.client_id:
            client_id = refresh.client_id

        expires_on = ""
        if access and access.expires_at:
            expires_on = access.expires_at.strftime("%Y-%m-%d %H:%M:%S")

        id_token = _extract_id_token(self.tokens)

        return {
            "_clientId": client_id,
            "_resource": resource,
            "accessToken": access.value if access else "",
            "refreshToken": refresh.value if refresh else "",
            "idToken": id_token,
            "tokenType": "Bearer",
            "expiresOn": expires_on,
            "tenantId": self.tenant_id or "",
            "userId": self.user_upn or "",
            "isMRRT": refresh.foci if refresh else False,
            "_authority": f"https://login.microsoftonline.com/{self.tenant_id or 'common'}",
        }

    # ----------------------------------------------------------------
    # Serialization (workspace persistence)
    # ----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dict for workspace storage."""
        return {
            "tenant_id": self.tenant_id,
            "user_upn": self.user_upn,
            "tokens": [_token_to_dict(t) for t in self.tokens],
            "device": _device_to_dict(self.device) if self.device else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EntraTokenStore:
        """Deserialize from workspace storage."""
        store = cls(
            tenant_id=data.get("tenant_id"),
            user_upn=data.get("user_upn"),
        )
        store.tokens = [_token_from_dict(t) for t in data.get("tokens", [])]
        if data.get("device"):
            store.device = _device_from_dict(data["device"])
        return store

    # ----------------------------------------------------------------
    # CAP guidance
    # ----------------------------------------------------------------

    @staticmethod
    def cap_guidance(error_code: str) -> str | None:
        """Return operator guidance for a known AADSTS CAP error code."""
        for code, guidance in CAP_ERRORS.items():
            if code in error_code:
                return f"[entra] Exchange failed: {code} — {guidance}"
        return None


# ----------------------------------------------------------------
# JWT utilities
# ----------------------------------------------------------------


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """Decode JWT payload without signature verification."""
    try:
        parts = token.split(".")

        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        try:
            return json.loads(decoded)
        except json.JSONDecodeError as je:
            logger.debug("Failed to decode JWT payload JSON: %s (Body: %s)", je, decoded[:100])
            raise ValueError(f"Invalid JWT payload JSON: {je}") from je
    except Exception as e:
        logger.debug("JWT decode failed: %s", e)
        return {}


def token_from_jwt(
    jwt: str,
    token_type: str,
    resource: str = "",
    client_id: str | None = None,
) -> EntraToken:
    """Build an EntraToken by decoding claims from a JWT."""
    claims = decode_jwt_claims(jwt)

    expires_at = None
    if "exp" in claims:
        try:
            expires_at = datetime.fromtimestamp(claims["exp"], tz=UTC)
        except (ValueError, OSError):
            pass

    scopes: list[str] = []
    if "scp" in claims:
        scopes = claims["scp"].split()
    elif "roles" in claims:
        scopes = claims.get("roles", [])

    device_claims = "deviceid" in claims or "join_type" in claims

    # FOCI detection: token is from a known FOCI client
    from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS

    detected_client = client_id or claims.get("appid") or claims.get("azp")
    is_foci = detected_client in FOCI_CLIENT_IDS if detected_client else False

    return EntraToken(
        token_type=token_type,
        value=jwt,
        resource=resource or claims.get("aud", ""),
        tenant_id=claims.get("tid"),
        client_id=detected_client,
        expires_at=expires_at,
        device_claims=device_claims,
        foci=is_foci,
        scopes=scopes,
        raw_claims=claims,
    )


# ----------------------------------------------------------------
# Resource matching (handle trailing slashes and scope suffixes)
# ----------------------------------------------------------------


def _resource_matches(stored: str, requested: str) -> bool:
    return stored.rstrip("/") == requested.rstrip("/")


# ----------------------------------------------------------------
# Serialization helpers
# ----------------------------------------------------------------


def _token_to_dict(tok: EntraToken) -> dict[str, Any]:
    return {
        "token_type": tok.token_type,
        "value": tok.value,
        "resource": tok.resource,
        "tenant_id": tok.tenant_id,
        "client_id": tok.client_id,
        "expires_at": tok.expires_at.isoformat() if tok.expires_at else None,
        "device_claims": tok.device_claims,
        "foci": tok.foci,
        "scopes": tok.scopes,
        "raw_claims": tok.raw_claims,
    }


def _token_from_dict(data: dict[str, Any]) -> EntraToken:
    expires_at = None
    if data.get("expires_at"):
        expires_at = datetime.fromisoformat(data["expires_at"])
    return EntraToken(
        token_type=data["token_type"],
        value=data["value"],
        resource=data.get("resource", ""),
        tenant_id=data.get("tenant_id"),
        client_id=data.get("client_id"),
        expires_at=expires_at,
        device_claims=data.get("device_claims", False),
        foci=data.get("foci", False),
        scopes=data.get("scopes", []),
        raw_claims=data.get("raw_claims", {}),
    )


def _device_to_dict(dev: EntraDeviceState) -> dict[str, Any]:
    return {
        "device_id": dev.device_id,
        "device_cert_pem": dev.device_cert_pem,
        "transport_key_pem": dev.transport_key_pem,
        "tenant_id": dev.tenant_id,
        "enrolled_at": dev.enrolled_at.isoformat(),
        "join_type": dev.join_type,
    }


def _device_from_dict(data: dict[str, Any]) -> EntraDeviceState:
    return EntraDeviceState(
        device_id=data["device_id"],
        device_cert_pem=data["device_cert_pem"],
        transport_key_pem=data["transport_key_pem"],
        tenant_id=data["tenant_id"],
        enrolled_at=datetime.fromisoformat(data["enrolled_at"]),
        join_type=data["join_type"],
    )


def _extract_id_token(tokens: list[EntraToken]) -> str:
    """Extract an id_token JWT from stored access tokens if available."""
    for tok in tokens:
        claims = tok.raw_claims
        if "email" in claims or "preferred_username" in claims:
            return tok.value
    return ""
