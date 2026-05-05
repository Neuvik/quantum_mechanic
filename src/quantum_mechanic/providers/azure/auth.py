# ================================================================
# MODULE: quantum_mechanic.providers.azure.auth
# ----------------------------------------------------------------
# PURPOSE:   Azure authentication and identity resolution.
#
#            Supports:
#              - DefaultAzureCredential (az login, env vars, MI)
#              - Client ID + secret (service principal)
#              - Refresh token import (for device code / phishing)
#
# DETECTION (Blue Team):
#   Azure AD Sign-in Logs: Look for token acquisitions from
#   unexpected IPs, user agents, or device states. The sign-in
#   log shows tenant, app, IP, and device compliance status.
# ================================================================

from __future__ import annotations

import json
import logging
from typing import Any

from azure.identity import (
    ClientSecretCredential,
    DefaultAzureCredential,
)
from azure.mgmt.subscription import SubscriptionClient

from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)


class AzureAuthProvider(AuthProvider):
    """Azure authentication provider.

    Handles credential loading and identity resolution via
    the Azure Resource Manager and subscription APIs.
    """

    @property
    def provider_name(self) -> str:
        return "azure"

    def authenticate(self, secret_data: dict[str, Any]) -> Any:
        """Create an Azure credential object.

        Args:
            secret_data: Must contain one of:
                - {"method": "default"}  — use DefaultAzureCredential
                - {"tenant_id": "...", "client_id": "...",
                   "client_secret": "..."}  — service principal
                - {"method": "cli"}  — use az login credentials

        Returns:
            Azure credential object (TokenCredential).

        Raises:
            ValueError: If required fields are missing.
        """
        method = secret_data.get("method", "")

        if method in ("default", "cli"):
            # --------------------------------------------------------
            # DefaultAzureCredential tries az login, env vars,
            # managed identity, etc. in order.
            # --------------------------------------------------------
            return DefaultAzureCredential()

        if "client_id" in secret_data and "client_secret" in secret_data:
            # --------------------------------------------------------
            # Service principal authentication.
            # --------------------------------------------------------
            tenant_id = secret_data.get("tenant_id")
            if not tenant_id:
                raise ValueError("Service principal auth requires 'tenant_id'")
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=secret_data["client_id"],
                client_secret=secret_data["client_secret"],
            )

        # --------------------------------------------------------
        # Fallback to DefaultAzureCredential if no explicit method.
        # --------------------------------------------------------
        return DefaultAzureCredential()

    def whoami(self, session: Any) -> WhoAmIResult:
        """Identify the Azure principal and tenant.

        Uses the Subscription client to enumerate accessible
        subscriptions, which reveals tenant and identity info.

        Args:
            session: Azure TokenCredential object.

        Returns:
            WhoAmIResult with Azure identity information.
        """
        credential = session

        # --------------------------------------------------------
        # Get a token to inspect claims. The token's 'oid' and
        # 'tid' fields tell us who we are and which tenant.
        # --------------------------------------------------------
        token = credential.get_token("https://management.azure.com/.default")

        # --------------------------------------------------------
        # Decode JWT claims (without verification — we just want
        # the payload for identity info, not to validate the sig).
        # --------------------------------------------------------
        import base64

        parts = token.token.split(".")
        if len(parts) >= 2:
            # --------------------------------------------------------
            # JWT payload is base64url-encoded. Add padding and decode.
            # --------------------------------------------------------
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        else:
            claims = {}

        # --------------------------------------------------------
        # Extract identity from JWT claims.
        #
        # Key claims:
        #   oid - Object ID (unique principal identifier)
        #   tid - Tenant ID
        #   upn - User Principal Name (for users)
        #   appid - Application ID (for service principals)
        #   sub - Subject
        # --------------------------------------------------------
        oid = claims.get("oid", "unknown")
        tid = claims.get("tid", "unknown")
        upn = claims.get("upn")
        appid = claims.get("appid")

        if upn:
            principal_type = "user"
            friendly_name = upn
        elif appid:
            principal_type = "service_principal"
            friendly_name = claims.get("app_displayname", appid)
        else:
            principal_type = "unknown"
            friendly_name = claims.get("sub", oid)

        # --------------------------------------------------------
        # List subscriptions to discover account scope.
        # --------------------------------------------------------
        subscriptions: list[dict[str, Any]] = []
        try:
            sub_client = SubscriptionClient(credential)
            for sub in sub_client.subscriptions.list():
                subscriptions.append(
                    {
                        "id": sub.subscription_id,
                        "name": sub.display_name,
                        "state": getattr(sub.state, "value", sub.state) if sub.state else "unknown",
                    }
                )
        except Exception as e:
            logger.warning("Could not list subscriptions: %s", e)

        # --------------------------------------------------------
        # Use first subscription as the "account" or fall back to
        # the tenant ID.
        # --------------------------------------------------------
        account_id = subscriptions[0]["id"] if subscriptions else tid
        account_name = subscriptions[0]["name"] if subscriptions else None

        return WhoAmIResult(
            provider="azure",
            principal_id=oid,
            principal_type=principal_type,
            friendly_name=friendly_name,
            account_id=account_id,
            account_name=account_name,
            tenant_id=tid,
            extra={
                "subscriptions": subscriptions,
                "claims": {k: v for k, v in claims.items() if k not in ("aio", "rh", "uti")},
            },
            raw_response=claims,
        )
