# ================================================================
# MODULE: quantum_mechanic.providers.cloud_error
# ----------------------------------------------------------------
# PURPOSE:   Classify cloud-provider SDK exceptions as "denied" vs
#            "error" so the runner can render the right glyph and
#            techniques can emit consistent status shapes.
#
#            AWS   boto3    -> ClientError with .response["Error"]["Code"]
#            GCP   google   -> google.api_core.exceptions.PermissionDenied
#            OCI   oci      -> oci.exceptions.ServiceError with .status
# ================================================================

from __future__ import annotations

from typing import Any

_AWS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "NotAuthorized",
    "InvalidAccessKeyId",
    "SignatureDoesNotMatch",
    "AuthFailure",
}


def classify_cloud_error(exc: Exception, provider: str) -> tuple[str, str, str]:
    """Classify a cloud SDK error.

    Returns (status, code, message) where status is "denied" or "error".
    Techniques feed the tuple into their return dict so the runner shows
    the right glyph and operators know whether to try re-auth vs retry.
    """
    provider = (provider or "").lower()

    if provider == "aws":
        # botocore.exceptions.ClientError.response["Error"]["Code"]
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            err = response.get("Error", {}) or {}
            code = err.get("Code", "Unknown")
            message = err.get("Message", str(exc))
            if code in _AWS_DENIED_CODES:
                return "denied", code, message
            return "error", code, message

    if provider == "gcp":
        # google.api_core.exceptions.PermissionDenied is a subclass of Forbidden.
        # We use string check to avoid importing google unconditionally.
        exc_type = type(exc).__name__
        if exc_type in ("PermissionDenied", "Unauthenticated", "Forbidden"):
            return "denied", exc_type, str(exc)
        return "error", exc_type, str(exc)

    if provider == "oci":
        status = getattr(exc, "status", None)
        code = getattr(exc, "code", "Unknown") or "Unknown"
        message = getattr(exc, "message", str(exc)) or str(exc)
        if status == 403 or code == "NotAuthorizedOrNotFound" or status == 401:
            return "denied", code, message
        return "error", code, message

    # Unknown provider — fall back to generic error.
    return "error", "Unknown", str(exc)


def cloud_error_to_result(
    exc: Exception, provider: str, **extra: Any
) -> dict[str, Any]:
    """Convert a cloud SDK exception into the standard technique result shape."""
    status, code, message = classify_cloud_error(exc, provider)
    return {
        "status": status,
        "error": f"{code}: {message}",
        "error_code": code,
        **extra,
    }
