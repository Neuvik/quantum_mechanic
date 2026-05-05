# ================================================================
# MODULE: quantum_mechanic.providers.oci.auth
# ----------------------------------------------------------------
# PURPOSE:   OCI (Oracle Cloud Infrastructure) authentication
#            and identity resolution.
#
#            Supports:
#              - Config file (~/.oci/config)
#              - Config file with named profile
#              - Inline config (from secret_data)
#              - Instance principal (for OCI instances)
#
# DETECTION (Blue Team):
#   OCI Audit Logs: Monitor GetUser, ListCompartments, and
#   GetTenancy calls. Look for API calls from unexpected IPs
#   or using unexpected API keys. OCI logs every API call in
#   the Audit service by default.
#   Key indicators:
#     - GetUser from non-corporate CIDR
#     - ListCompartments from service accounts that shouldn't
#       be enumerating the tenancy
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import oci

from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)


class OCIAuthProvider(AuthProvider):
    """OCI authentication provider.

    Handles credential loading and identity resolution via
    the OCI Identity service.
    """

    @property
    def provider_name(self) -> str:
        return "oci"

    def authenticate(self, secret_data: dict[str, Any]) -> dict[str, Any]:
        """Create OCI configuration and signer.

        Args:
            secret_data: Must contain one of:
                - {"method": "config_file"}  — use ~/.oci/config
                - {"method": "config_file", "profile": "PROFILE"}
                - {"method": "config_file",
                   "config_file": "/path/to/config"}
                - {"method": "instance_principal"}
                - {"user": "...", "tenancy": "...",
                   "fingerprint": "...", "key_content": "...",
                   "region": "..."}

        Returns:
            Dict with "config" and "signer" keys for OCI SDK clients.

        Raises:
            ValueError: If required fields are missing.
        """
        method = secret_data.get("method", "")

        if method == "instance_principal":
            # --------------------------------------------------------
            # Instance principal — for workloads running on OCI.
            # --------------------------------------------------------
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {"region": signer.region}
            return {"config": config, "signer": signer}

        if method == "config_file" or not method:
            # --------------------------------------------------------
            # Config file — default ~/.oci/config or custom path.
            # --------------------------------------------------------
            config_file = secret_data.get("config_file", oci.config.DEFAULT_LOCATION)
            profile = secret_data.get("profile", "DEFAULT")

            config = oci.config.from_file(
                file_location=config_file,
                profile_name=profile,
            )
            oci.config.validate_config(config)
            return {"config": config, "signer": None}

        # --------------------------------------------------------
        # Inline config — all fields provided directly.
        # --------------------------------------------------------
        required = ["user", "tenancy", "fingerprint", "key_content", "region"]
        missing = [f for f in required if f not in secret_data]
        if missing:
            raise ValueError(f"OCI inline config requires: {', '.join(missing)}")

        config = {
            "user": secret_data["user"],
            "tenancy": secret_data["tenancy"],
            "fingerprint": secret_data["fingerprint"],
            "key_content": secret_data["key_content"],
            "region": secret_data["region"],
        }
        if "pass_phrase" in secret_data:
            config["pass_phrase"] = secret_data["pass_phrase"]

        oci.config.validate_config(config)
        return {"config": config, "signer": None}

    def whoami(self, session: Any) -> WhoAmIResult:
        """Identify the OCI principal.

        Calls Identity.get_user() for the configured user OCID,
        then GetTenancy for tenancy details.

        Args:
            session: Dict with "config" and optional "signer".

        Returns:
            WhoAmIResult with OCI identity information.
        """
        config = session["config"]
        signer = session.get("signer")

        # --------------------------------------------------------
        # Build the identity client. If we have a signer
        # (instance principal), use it. Otherwise default.
        # --------------------------------------------------------
        if signer:
            identity_client = oci.identity.IdentityClient(config={}, signer=signer)
        else:
            identity_client = oci.identity.IdentityClient(config)

        # --------------------------------------------------------
        # Get user details.
        # --------------------------------------------------------
        user_ocid = config.get("user", "")
        friendly_name = "unknown"
        principal_type = "unknown"
        email = None
        raw_response: dict[str, Any] = {}

        if user_ocid:
            try:
                user_response = identity_client.get_user(user_ocid)
                user = user_response.data
                friendly_name = user.name
                email = getattr(user, "email", None)
                principal_type = "user"
                raw_response["user"] = {
                    "id": user.id,
                    "name": user.name,
                    "email": email,
                    "lifecycle_state": user.lifecycle_state,
                    "is_mfa_activated": getattr(user, "is_mfa_activated", None),
                    "time_created": str(user.time_created),
                }
            except oci.exceptions.ServiceError as e:
                logger.warning("get_user failed: %s", e.message)
                # Might be instance principal — no user OCID
                if signer:
                    principal_type = "instance_principal"
                    friendly_name = "instance-principal"
                else:
                    principal_type = "user"
                    friendly_name = "unknown-user"
        elif signer:
            principal_type = "instance_principal"
            friendly_name = "instance-principal"

        # --------------------------------------------------------
        # Get tenancy details.
        # --------------------------------------------------------
        tenancy_id = config.get("tenancy", "")
        tenancy_name = None

        if tenancy_id:
            try:
                tenancy_response = identity_client.get_tenancy(tenancy_id)
                tenancy = tenancy_response.data
                tenancy_name = tenancy.name
                raw_response["tenancy"] = {
                    "id": tenancy.id,
                    "name": tenancy.name,
                    "home_region_key": getattr(tenancy, "home_region_key", None),
                }
            except oci.exceptions.ServiceError as e:
                logger.warning("get_tenancy failed: %s", e.message)

        return WhoAmIResult(
            provider="oci",
            principal_id=user_ocid or "instance-principal",
            principal_type=principal_type,
            friendly_name=friendly_name,
            account_id=tenancy_id or "unknown",
            account_name=tenancy_name,
            tenant_id=tenancy_id or None,
            extra={
                "email": email,
                "region": config.get("region"),
                "fingerprint": config.get("fingerprint"),
            },
            raw_response=raw_response or None,
        )
