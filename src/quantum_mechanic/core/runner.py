# ================================================================
# MODULE: quantum_mechanic.core.runner
# ----------------------------------------------------------------
# PURPOSE:   Technique execution engine. Takes a technique ID and
#            executes it against the active workspace/credential,
#            building the execution context and returning results.
#
# DESIGN:    The runner is the bridge between the shell/agent
#            and the technique functions. It handles context
#            construction, error handling, and result formatting.
# ================================================================

from __future__ import annotations

import contextlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry

logger = logging.getLogger(__name__)


@dataclass
class TechniqueResult:
    """Result of executing a technique."""

    technique_id: str
    provider: str
    status: str  # "success", "error", "skipped"
    operator: str | None = None  # authenticated operator (audit attribution)
    data: Any = None  # Technique-specific result data
    error: str | None = None
    api_calls: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization."""
        result: dict[str, Any] = {
            "technique": self.technique_id,
            "provider": self.provider,
            "status": self.status,
            "api_calls": self.api_calls,
            "duration_ms": self.duration_ms,
        }
        if self.data is not None:
            # --------------------------------------------------------
            # Handle WhoAmIResult and other dataclasses by converting
            # to dict. Plain dicts pass through.
            # --------------------------------------------------------
            if hasattr(self.data, "__dataclass_fields__"):
                from dataclasses import asdict

                result["data"] = asdict(self.data)
            elif isinstance(self.data, dict):
                result["data"] = self.data
            else:
                result["data"] = str(self.data)
        if self.error:
            result["error"] = self.error
        return result


class TechniqueRunner:
    """Executes techniques against the active workspace and credential.

    The runner builds the execution context, validates that the
    technique supports the active provider, runs the technique
    function, and returns a structured result.
    """

    def __init__(
        self,
        workspace: Workspace,
        loader: TechniqueLoader,
        registry: ProviderRegistry,
    ) -> None:
        self.workspace = workspace
        self.loader = loader
        self.registry = registry

    # ================================================================
    # Public API
    # ================================================================

    def run(
        self,
        technique_id: str,
        credential_id: int | None = None,
        *,
        safe_mode: bool = False,
        params: dict | None = None,
        operator: str | None = None,
    ) -> TechniqueResult:
        """Execute a technique.

        Args:
            technique_id: ID of the technique to run.
            credential_id: Override active credential. Uses
                workspace's active credential if not specified.
            safe_mode: If True, run in check-only mode.
            params: Arbitrary key/value parameters passed to ctx.params.
            operator: Authenticated operator name for audit attribution.

        Returns:
            TechniqueResult with status and data.
        """
        start = time.monotonic()

        # --- Resolve technique ------------------------------------------
        registered = self._resolve_technique(technique_id)
        if registered is None:
            return TechniqueResult(
                technique_id=technique_id,
                provider="unknown",
                status="error",
                error=f"Technique '{technique_id}' not found. Run 'techniques' to see available.",
            )

        # --- Resolve credential -----------------------------------------
        cred_id = credential_id or self.workspace.active_credential_id
        cred, err = self._resolve_credential(technique_id, cred_id, registered)
        if err is not None:
            return err

        # --- Authenticate -----------------------------------------------
        session, err = self._build_session(technique_id, cred_id, cred)
        if err is not None:
            return err

        # --- Build execution context ------------------------------------
        ctx = ExecutionContext(
            workspace=self.workspace,
            credential_id=cred_id,
            provider=self.registry.get(cred.provider),
            session=session,
            technique_id=technique_id,
            safe_mode=safe_mode,
            params=params,
        )

        # --- Execute technique ------------------------------------------
        try:
            result_data = registered.function(ctx)
            duration_ms = int((time.monotonic() - start) * 1000)

            if result_data is not None:
                try:
                    self._persist_evidence(
                        registered=registered,
                        technique_id=technique_id,
                        cred=cred,
                        cred_id=cred_id,
                        result_data=result_data,
                        duration_ms=duration_ms,
                        ctx=ctx,
                    )
                except Exception as ev_err:
                    logger.warning("Evidence write failed for %s: %s", technique_id, ev_err)

            return TechniqueResult(
                technique_id=technique_id,
                provider=cred.provider,
                operator=operator,
                status="success",
                data=result_data,
                api_calls=ctx.api_call_count,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            friendly = _friendly_error(e, cred.provider)
            logger.debug("Technique %s failed: %s", technique_id, e)
            return TechniqueResult(
                technique_id=technique_id,
                provider=cred.provider,
                operator=operator,
                status="error",
                error=friendly,
                api_calls=ctx.api_call_count,
                duration_ms=duration_ms,
            )

    # ================================================================
    # Private helpers — each has a single responsibility
    # ================================================================

    def _resolve_technique(self, technique_id: str):
        """Look up the technique in the loader registry.

        Returns the registered technique or None if not found.
        """
        return self.loader.get(technique_id)

    def _resolve_credential(
        self,
        technique_id: str,
        cred_id: int | None,
        registered,
    ) -> tuple:
        """Validate that we have an active, compatible credential.

        Returns (credential, None) on success, or (None, TechniqueResult)
        when an error must be returned to the caller.
        """
        if cred_id is None:
            return None, TechniqueResult(
                technique_id=technique_id,
                provider="unknown",
                status="error",
                error="No active credential. Run 'use <id>' to select one.",
            )

        cred = self.workspace.get_credential(cred_id)
        if cred is None:
            return None, TechniqueResult(
                technique_id=technique_id,
                provider="unknown",
                status="error",
                error=f"Credential #{cred_id} not found.",
            )

        if cred.provider not in registered.metadata.providers:
            supported = ", ".join(registered.metadata.providers)
            return None, TechniqueResult(
                technique_id=technique_id,
                provider=cred.provider,
                status="error",
                error=(
                    f"Technique '{technique_id}' does not support provider "
                    f"'{cred.provider}'. Supported: {supported}"
                ),
            )

        return cred, None

    def _build_session(
        self,
        technique_id: str,
        cred_id: int,
        cred,
    ) -> tuple:
        """Retrieve credential secrets and authenticate with the provider.

        Returns (session, None) on success, or (None, TechniqueResult)
        when an error must be returned to the caller.
        """
        provider = self.registry.get(cred.provider)
        if provider is None:
            return None, TechniqueResult(
                technique_id=technique_id,
                provider=cred.provider,
                status="error",
                error=f"Provider '{cred.provider}' not available.",
            )

        try:
            secret_data_raw = self.workspace.get_credential_secret(cred_id)
            if secret_data_raw is None:
                return None, TechniqueResult(
                    technique_id=technique_id,
                    provider=cred.provider,
                    status="error",
                    error=f"No secret data for credential #{cred_id}.",
                )
            secret_data = json.loads(secret_data_raw)
            session = provider.authenticate(secret_data)
            return session, None
        except Exception as e:
            return None, TechniqueResult(
                technique_id=technique_id,
                provider=cred.provider,
                status="error",
                error=f"Authentication failed: {e}",
            )

    def _persist_evidence(
        self,
        *,
        registered,
        technique_id: str,
        cred,
        cred_id: int,
        result_data,
        duration_ms: int,
        ctx: ExecutionContext,
    ) -> None:
        """Write all evidence artifacts for a successful technique run.

        Covers:
          1. Raw JSON to the evidence table (for RAG / queries).
          2. Technique-specific structured DB writes (compute, network).
          3. Rich markdown note to the workspace directory.
          4. Structured finding rows from risk flags.
          5. Re-render of ATTACK_PATH.md from the updated DB.
        """
        # Normalise result to a plain dict once for all evidence paths.
        if hasattr(result_data, "__dataclass_fields__"):
            from dataclasses import asdict
            dump_data: dict = asdict(result_data)
        elif isinstance(result_data, dict):
            dump_data = result_data
        else:
            dump_data = {"raw": str(result_data)}

        raw_json = json.dumps(dump_data, default=str)

        # 1. Raw JSON → evidence table
        self.workspace.save_evidence(
            technique_id=technique_id,
            output_json=raw_json,
            credential_id=cred_id,
        )

        # 2. Technique-specific structured writes
        self._write_structured_assets(technique_id, cred, dump_data)

        # 3. Markdown note + 4. findings rows
        from pathlib import Path as _Path

        from quantum_mechanic.agent.summarizer import summarize as _sum
        from quantum_mechanic.evidence import attack_path as _ap
        from quantum_mechanic.evidence import writer as _wr

        workspace_dir = _Path(self.workspace.workspace_dir)
        tactic = registered.metadata.tactic
        agent_summary = _sum(
            technique_id=technique_id,
            tactic=tactic,
            provider=cred.provider,
            data=dump_data,
            ok=True,
            ms=duration_ms,
            api_calls=ctx.api_call_count,
        )
        principal = (
            dump_data.get("principal")
            or dump_data.get("friendly_name")
            or cred.friendly_name
            or "unknown"
        )
        _wr.write_technique_note(
            workspace_dir=workspace_dir,
            technique_id=technique_id,
            tactic=tactic,
            provider=cred.provider,
            principal=principal,
            summary=agent_summary.summary,
            risk_flags=agent_summary.risk_flags,
            raw_data=dump_data,
            duration_ms=duration_ms,
            api_calls=ctx.api_call_count,
        )

        # 4. Finding rows from risk flags
        self._write_findings(
            technique_id=technique_id,
            tactic=tactic,
            cred=cred,
            principal=principal,
            agent_summary=agent_summary,
        )

        # 5. Re-render ATTACK_PATH.md
        _ap.render(self.workspace, workspace_dir)

    def _write_structured_assets(
        self,
        technique_id: str,
        cred,
        dump_data: dict,
    ) -> None:
        """Persist structured compute / network assets for known techniques.

        Centralises the technique_id dispatch that previously lived inline
        inside run(). Add new technique-specific writers here.
        """
        if technique_id != "discovery/enum_compute":
            return

        import json as _json

        provider = dump_data.get("provider", cred.provider)
        for inst in dump_data.get("instances", []):
            sgs = inst.get("security_group_ids", [])
            profile_arn = inst.get("instance_profile_arn") or inst.get("identity")
            profile_name = (
                profile_arn.split("/")[-1]
                if profile_arn and "/" in profile_arn
                else profile_arn
            )
            self.workspace.upsert_compute_instance(
                provider=provider,
                instance_id=(
                    inst.get("instance_id")
                    or inst.get("id")
                    or inst.get("vm_id", "unknown")
                ),
                name=inst.get("name") or inst.get("display_name"),
                state=inst.get("state") or inst.get("lifecycle_state"),
                instance_type=(
                    inst.get("type")
                    or inst.get("machine_type")
                    or inst.get("shape")
                ),
                private_ip=inst.get("private_ip"),
                public_ip=inst.get("public_ip"),
                subnet_id=inst.get("subnet_id"),
                image_id=inst.get("image_id"),
                identity_arn=profile_arn,
                identity_name=profile_name,
                security_group_ids=_json.dumps(sgs, default=str),
                metadata=_json.dumps(inst, default=str),
            )
            if inst.get("subnet_id"):
                self.workspace.upsert_network_asset(
                    provider=provider,
                    asset_type="subnet",
                    asset_id=inst["subnet_id"],
                )
            for sg in sgs:
                self.workspace.upsert_network_asset(
                    provider=provider,
                    asset_type="security_group",
                    asset_id=sg,
                )

    def _write_findings(
        self,
        *,
        technique_id: str,
        tactic: str,
        cred,
        principal: str,
        agent_summary,
    ) -> None:
        """Persist structured finding rows for each risk flag.

        Severity mapping:
          - rce:* / root → critical
          - Known high-privilege flags → high
          - Everything else → medium
        """
        import json as _json

        _HIGH_SEVERITY_FLAGS = {
            "AdministratorAccess", "IAMFullAccess",
            "PowerUserAccess", "rce:confirmed", "rce:root_context",
            "role:Owner", "role:Contributor",
            "role:User Access Administrator",
            "role:roles/owner", "role:roles/editor",
        }

        for flag in agent_summary.risk_flags:
            if any(h in flag for h in ("rce:", "root")):
                sev = "critical"
            elif any(h in flag for h in _HIGH_SEVERITY_FLAGS):
                sev = "high"
            else:
                sev = "medium"

            flag_value = flag.split(":", 1)[-1] if ":" in flag else flag
            flag_key = flag.split(":", 1)[0] if ":" in flag else flag
            human_title: str = {
                "policy":           f"Privileged Policy: {flag_value}",
                "assumed":          f"IAM Role Assumed: {flag_value}",
                "role":             f"Privileged Role: {flag_value}",
                "group":            f"Privileged Group: {flag_value}",
                "role_chain_depth": f"Role Chain Depth: {flag_value} hops",
                "rce":              f"Remote Code Execution: {flag_value.replace('_', ' ')}",
            }.get(flag_key, f"{flag_key.replace('_', ' ').title()}: {flag_value}")

            self.workspace.add_finding(
                technique_id=technique_id,
                tactic=tactic,
                title=human_title,
                severity=sev,
                provider=cred.provider,
                description=agent_summary.summary,
                evidence=_json.dumps(
                    {"flag": flag, "principal": principal, "summary": agent_summary.summary},
                    default=str,
                ),
            )


# ================================================================
# Provider-specific error translation.
# Maps raw SDK exceptions to operator-friendly messages.
# ================================================================

# AWS error code → (short message, action hint)
_AWS_ERROR_MAP: dict[str, tuple[str, str]] = {
    "InvalidClientTokenId": (
        "Invalid AWS credentials",
        "The access key ID does not exist. Check your profile or re-import with valid keys.",
    ),
    "SignatureDoesNotMatch": (
        "Invalid AWS secret key",
        "The secret access key is wrong. Re-import the correct key pair.",
    ),
    "ExpiredToken": (
        "AWS session token expired",
        "The temporary credentials have expired. Obtain fresh STS tokens and re-import.",
    ),
    "ExpiredTokenException": (
        "AWS session token expired",
        "The temporary credentials have expired. Obtain fresh STS tokens and re-import.",
    ),
    "AccessDenied": (
        "Access denied",
        "The credentials are valid but lack permission for this operation.",
    ),
    "UnauthorizedAccess": (
        "Unauthorized",
        "The credentials are not authorized for this action.",
    ),
}


def _friendly_error(exc: Exception, provider: str) -> str:
    """Translate a provider SDK exception to a human-friendly message.

    Returns a clear one-liner instead of a raw stack trace. The
    operator doesn't need to see botocore internals — they need
    to know what's wrong and what to do about it.
    """
    exc_type = type(exc).__name__

    # --------------------------------------------------------
    # AWS: botocore.exceptions.ClientError
    # --------------------------------------------------------
    if provider == "aws" and exc_type == "ClientError":
        # botocore ClientError has response['Error']['Code']
        error_code = ""
        with contextlib.suppress(AttributeError, KeyError, TypeError):
            error_code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]

        if error_code in _AWS_ERROR_MAP:
            short, hint = _AWS_ERROR_MAP[error_code]
            return f"{short}: {hint}"

        # Unknown AWS error — still clean it up
        return f"AWS API error ({error_code}): {exc}"

    # --------------------------------------------------------
    # AWS: botocore.exceptions.NoCredentialsError
    # --------------------------------------------------------
    if exc_type == "NoCredentialsError":
        return (
            "No AWS credentials found: The specified profile or "
            "environment variables don't contain valid credentials. "
            "Run 'aws configure' or re-import with --access-key."
        )

    # --------------------------------------------------------
    # AWS: botocore.exceptions.ProfileNotFound
    # --------------------------------------------------------
    if exc_type == "ProfileNotFound":
        return f"AWS profile not found: {exc}. Check ~/.aws/credentials for available profiles."

    # --------------------------------------------------------
    # Azure: azure.core.exceptions.ClientAuthenticationError
    # --------------------------------------------------------
    if exc_type == "ClientAuthenticationError":
        return (
            "Azure authentication failed: The credentials are invalid "
            "or expired. If using 'az login', try re-authenticating. "
            "For service principals, verify client_id and client_secret."
        )

    # --------------------------------------------------------
    # Azure: azure.core.exceptions.HttpResponseError
    # --------------------------------------------------------
    if exc_type == "HttpResponseError":
        return f"Azure API error: {exc}"

    # --------------------------------------------------------
    # GCP: google.auth.exceptions.DefaultCredentialsError
    # --------------------------------------------------------
    if exc_type == "DefaultCredentialsError":
        return (
            "No GCP credentials found: Run 'gcloud auth application-default login' "
            "or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file."
        )

    # --------------------------------------------------------
    # GCP: google.auth.exceptions.RefreshError
    # --------------------------------------------------------
    if exc_type == "RefreshError":
        return (
            "GCP credentials expired or invalid: "
            "Run 'gcloud auth application-default login' to re-authenticate."
        )

    # --------------------------------------------------------
    # GCP: google.api_core.exceptions.*
    # --------------------------------------------------------
    if exc_type in ("PermissionDenied", "Forbidden"):
        return f"GCP permission denied: {exc}"

    # --------------------------------------------------------
    # OCI: oci.exceptions.ServiceError
    # --------------------------------------------------------
    if exc_type == "ServiceError":
        status = getattr(exc, "status", None)
        code = getattr(exc, "code", "")
        message = getattr(exc, "message", str(exc))
        if status == 401 or code == "NotAuthenticated":
            return (
                "OCI authentication failed: Check your API key, fingerprint, "
                "and tenancy OCID in ~/.oci/config."
            )
        if status == 404:
            return (
                f"OCI resource not found: {message}. "
                f"Verify user OCID and tenancy OCID in your config."
            )
        return f"OCI API error ({status} {code}): {message}"

    # --------------------------------------------------------
    # OCI: oci.exceptions.ConfigFileNotFound
    # --------------------------------------------------------
    if exc_type == "ConfigFileNotFound":
        return (
            "OCI config file not found: Expected ~/.oci/config. "
            "Run 'oci setup config' to create one."
        )

    # --------------------------------------------------------
    # Connection / network errors
    # --------------------------------------------------------
    if exc_type in ("ConnectionError", "EndpointConnectionError"):
        return (
            "Network error: Could not reach the cloud provider API. "
            "Check your internet connection and proxy settings."
        )

    if exc_type == "ReadTimeoutError":
        return (
            "Timeout: The API call timed out. The provider may be "
            "experiencing issues, or your network is slow."
        )

    # --------------------------------------------------------
    # Fallback — still no stack trace, just the message.
    # --------------------------------------------------------
    return f"Error: {exc}"
