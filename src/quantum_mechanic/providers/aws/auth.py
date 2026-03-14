# ================================================================
# MODULE: quantum_mechanic.providers.aws.auth
# ----------------------------------------------------------------
# PURPOSE:   AWS authentication and identity resolution.
#
#            Supports:
#              - Access key + secret key (IAM user)
#              - Access key + secret key + session token (STS)
#              - Named profile from ~/.aws/credentials
#              - Environment variables (AWS_ACCESS_KEY_ID, etc.)
#
# DETECTION (Blue Team):
#   CloudTrail: sts:GetCallerIdentity
#   This is a benign call but unusual from unexpected source IPs.
#   Monitor for GetCallerIdentity from IPs outside your corporate
#   ranges — it's often the first thing an attacker runs.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import boto3

from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)


class AWSAuthProvider(AuthProvider):
    """AWS authentication provider.

    Handles credential loading and identity resolution via STS.
    """

    @property
    def provider_name(self) -> str:
        return "aws"

    def authenticate(self, secret_data: dict[str, Any]) -> boto3.Session:
        """Create a boto3 Session from credential data.

        Args:
            secret_data: Must contain one of:
                - {"profile_name": "..."}  — use named profile
                - {"access_key_id": "...", "secret_access_key": "..."}
                - {"access_key_id": "...", "secret_access_key": "...",
                   "session_token": "..."}

        Returns:
            Authenticated boto3.Session.

        Raises:
            ValueError: If required fields are missing.
            botocore.exceptions.ClientError: If credentials are invalid.
        """
        if "profile_name" in secret_data:
            # --------------------------------------------------------
            # Load from named AWS CLI profile (~/.aws/credentials).
            # --------------------------------------------------------
            return boto3.Session(
                profile_name=secret_data["profile_name"],
                region_name=secret_data.get("region", "us-east-1"),
            )

        if "access_key_id" not in secret_data:
            raise ValueError(
                "AWS credentials must include 'profile_name' or "
                "'access_key_id' + 'secret_access_key'"
            )

        return boto3.Session(
            aws_access_key_id=secret_data["access_key_id"],
            aws_secret_access_key=secret_data["secret_access_key"],
            aws_session_token=secret_data.get("session_token"),
            region_name=secret_data.get("region", "us-east-1"),
        )

    def whoami(self, session: Any) -> WhoAmIResult:
        """Call sts:GetCallerIdentity and return normalized result.

        Args:
            session: Authenticated boto3.Session.

        Returns:
            WhoAmIResult with AWS identity information.

        Raises:
            botocore.exceptions.ClientError: If the call fails.
        """
        sts = session.client("sts")
        response = sts.get_caller_identity()

        # --------------------------------------------------------
        # Parse the ARN to extract the principal type and name.
        #
        # ARN formats:
        #   arn:aws:iam::123456789012:user/username
        #   arn:aws:iam::123456789012:role/rolename
        #   arn:aws:sts::123456789012:assumed-role/rolename/session
        #   arn:aws:iam::123456789012:root
        # --------------------------------------------------------
        arn = response["Arn"]
        account_id = response["Account"]
        user_id = response["UserId"]

        principal_type, friendly_name = self._parse_arn(arn)

        return WhoAmIResult(
            provider="aws",
            principal_id=arn,
            principal_type=principal_type,
            friendly_name=friendly_name,
            account_id=account_id,
            extra={"user_id": user_id},
            raw_response=response,
        )

    @staticmethod
    def _parse_arn(arn: str) -> tuple[str, str]:
        """Parse an AWS ARN into (principal_type, friendly_name).

        Args:
            arn: AWS ARN string.

        Returns:
            Tuple of (type, name) for display.
        """
        # arn:aws:iam::123456789012:user/username
        # arn:aws:sts::123456789012:assumed-role/rolename/session
        parts = arn.split(":")
        if len(parts) < 6:
            return "unknown", arn

        resource = parts[5]

        if resource == "root":
            return "root", "root (account owner)"
        elif resource.startswith("user/"):
            return "user", resource.split("/", 1)[1]
        elif resource.startswith("role/"):
            return "role", resource.split("/", 1)[1]
        elif resource.startswith("assumed-role/"):
            # assumed-role/RoleName/SessionName
            role_parts = resource.split("/")
            role_name = role_parts[1] if len(role_parts) > 1 else resource
            return "assumed_role", role_name
        elif resource.startswith("federated-user/"):
            return "federated_user", resource.split("/", 1)[1]
        else:
            return "unknown", resource
