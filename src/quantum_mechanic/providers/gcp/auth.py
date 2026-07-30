# ================================================================
# MODULE: quantum_mechanic.providers.gcp.auth
# ----------------------------------------------------------------
# PURPOSE:   GCP authentication and identity resolution.
#
#            Supports:
#              - Application Default Credentials (gcloud auth)
#              - Service account JSON key file
#              - Service account JSON inline (from secret_data)
#
# DETECTION (Blue Team):
#   Cloud Audit Logs: Look for tokeninfo or IAM API calls from
#   unexpected IPs or service accounts. GCP logs every token
#   acquisition in the Access Transparency logs if enabled.
#   Monitor serviceAccounts.getAccessToken and
#   projects.serviceAccounts.signBlob for lateral movement.
# ================================================================

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import google.auth  # noqa: F401 — kept for test patch path stability
from google.auth.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as TokenCredentials

from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)


class GCPAuthProvider(AuthProvider):
    """GCP authentication provider.

    Handles credential loading and identity resolution via
    Google Cloud IAM and token introspection.
    """

    @property
    def provider_name(self) -> str:
        return "gcp"

    def authenticate(self, secret_data: dict[str, Any]) -> Credentials:
        """Create GCP credentials from secret data.

        Args:
            secret_data: Must contain one of:
                - {"method": "captured_token",
                   "access_token": "ya29...."} — token captured at import time
                - {"method": "service_account_file",
                   "key_file": "/path/to/key.json"}
                - {"method": "service_account_info",
                   "service_account_info": {...}}  — inline SA JSON
                - {"method": "access_token",
                   "access_token": "ya29...."}

        NOTE: {"method": "default"} is REFUSED. That value referenced local
        gcloud ADC state at use-time and silently substituted whoever was
        currently logged in — a credential-isolation bug. Re-import via
        `import gcp --default` to capture the token at import time.

        Returns:
            Google auth Credentials object.

        Raises:
            ValueError: If required fields are missing, the method references
                local gcloud state, or the method is unknown.
        """
        method = secret_data.get("method", "")

        if method == "default":
            raise ValueError(
                "GCP credential has method='default' which references local "
                "gcloud ADC state. Re-import via `import gcp --default` to "
                "capture the token at import time."
            )

        if method == "":
            raise ValueError(
                "GCP credential has no method set — this is a stale credential "
                "format from before the credential-isolation fix. "
                "Re-import via `import gcp --default`."
            )

        if method == "captured_token":
            token = secret_data.get("access_token")
            if not token:
                raise ValueError("GCP captured_token method requires 'access_token'")
            
            from datetime import datetime, timedelta
            # Provide an arbitrary future expiry so Google SDK clients don't
            # attempt to automatically refresh this static token.
            # Using naive UTC datetime as expected by google-auth.
            future_expiry = datetime.utcnow() + timedelta(hours=1)
            class StaticTokenCredentials(TokenCredentials):
                def refresh(self, request):
                    raise ValueError(
                        "This GCP token was captured statically via `import gcp --default` "
                        "and has expired. Please run `import gcp --default` again to capture "
                        "a fresh token."
                    )
            
            cred = StaticTokenCredentials(token, expiry=future_expiry)
            if "project_id" in secret_data:
                cred.project_id = secret_data["project_id"]
            return cred

        if method == "service_account_file":
            key_file = secret_data.get("key_file")
            if not key_file:
                raise ValueError("GCP service_account_file method requires 'key_file' path")
            if not Path(key_file).exists():
                raise ValueError(f"Service account key file not found: {key_file}")
            return service_account.Credentials.from_service_account_file(
                key_file,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )

        if method == "service_account_info":
            sa_info = secret_data.get("service_account_info")
            if not sa_info:
                raise ValueError(
                    "GCP service_account_info method requires 'service_account_info' dict"
                )
            if isinstance(sa_info, str):
                sa_info = json.loads(sa_info)
            return service_account.Credentials.from_service_account_info(
                sa_info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )

        if method == "access_token":
            token = secret_data.get("access_token")
            if not token:
                raise ValueError("GCP access_token method requires 'access_token' string")
            return TokenCredentials(token)

        raise ValueError(
            f"Unknown GCP auth method: {method}. "
            f"Use: default, service_account_file, service_account_info, access_token"
        )

    def whoami(self, session: Any) -> WhoAmIResult:
        """Identify the GCP principal.

        For service accounts: reads the email and project from
        the credential object directly.
        For user credentials: refreshes the token and inspects it.

        Args:
            session: Google auth Credentials object.

        Returns:
            WhoAmIResult with GCP identity information.
        """
        credentials = session

        # --------------------------------------------------------
        # Refresh the credentials to ensure they're valid and
        # to populate token metadata.
        # --------------------------------------------------------
        request = Request()
        if not (isinstance(credentials, TokenCredentials) and not credentials.refresh_token):
            credentials.refresh(request)

        # --------------------------------------------------------
        # Extract identity from the credential object.
        # Service account credentials have .service_account_email
        # and .project_id directly.
        # User credentials have .token which we can introspect.
        # --------------------------------------------------------
        if hasattr(credentials, "service_account_email"):
            # Service account credential
            email = credentials.service_account_email
            project_id = getattr(credentials, "project_id", None) or "unknown"
            principal_type = "service_account"
            friendly_name = email.split("@")[0] if email else "unknown"
        else:
            # User or other credential type — use tokeninfo
            email, project_id, principal_type, friendly_name = self._resolve_user_identity(
                credentials, request
            )

        # Override project_id if it was explicitly passed during import
        explicit_project = getattr(credentials, "project_id", None)
        if explicit_project:
            project_id = explicit_project

        return WhoAmIResult(
            provider="gcp",
            principal_id=email or "unknown",
            principal_type=principal_type,
            friendly_name=friendly_name,
            account_id=project_id or "unknown",
            extra={
                "email": email,
                "project_id": project_id,
                "scopes": getattr(credentials, "scopes", None),
            },
        )

    @staticmethod
    def _resolve_user_identity(
        credentials: Any,
        request: Request,
    ) -> tuple[str, str | None, str, str]:
        """Resolve identity for user (non-SA) credentials.

        Uses the Google OAuth2 tokeninfo endpoint.

        Returns:
            (email, project_id, principal_type, friendly_name)
        """
        import urllib.request

        token = credentials.token
        if not token:
            return ("unknown", None, "unknown", "unknown")

        # --------------------------------------------------------
        # Call the tokeninfo endpoint to get the email and scope.
        # This is a lightweight call that doesn't require any
        # IAM permissions.
        # --------------------------------------------------------
        try:
            tokeninfo_url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
            req = urllib.request.Request(tokeninfo_url)  # noqa: S310
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                info = json.loads(resp.read())

            email = info.get("email", "unknown")
            principal_type = "user"
            if info.get("email_verified") == "false":
                principal_type = "unverified_user"

            # Extract project from the audience or sub
            project_id = info.get("azp") or info.get("aud")
            friendly_name = email.split("@")[0] if email else "unknown"

            return (email, project_id, principal_type, friendly_name)
        except Exception as e:
            logger.warning("tokeninfo lookup failed: %s", e)
            return ("unknown", None, "unknown", "unknown")
