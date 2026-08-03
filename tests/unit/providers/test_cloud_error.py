"""Tests for the cloud SDK error classifier."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from quantum_mechanic.providers.cloud_error import (
    classify_cloud_error,
    cloud_error_to_result,
)


def _aws_client_error(code: str, message: str = "denied by IAM") -> Exception:
    """Fake botocore.exceptions.ClientError shape without importing botocore."""
    exc = Exception(f"{code}: {message}")
    exc.response = {"Error": {"Code": code, "Message": message}}
    return exc


def test_aws_access_denied_is_denied():
    """OUTCOME: boto3 ClientError with AccessDenied → status='denied'."""
    status, code, msg = classify_cloud_error(_aws_client_error("AccessDenied"), "aws")
    assert status == "denied"
    assert code == "AccessDenied"


def test_aws_unauthorized_operation_is_denied():
    """OUTCOME: EC2's UnauthorizedOperation code → status='denied' (not 'error')."""
    status, _, _ = classify_cloud_error(_aws_client_error("UnauthorizedOperation"), "aws")
    assert status == "denied"


def test_aws_throttling_is_error_not_denied():
    """OUTCOME: Non-permission errors like Throttling are 'error', not 'denied'."""
    status, code, _ = classify_cloud_error(_aws_client_error("Throttling"), "aws")
    assert status == "error"
    assert code == "Throttling"


def test_gcp_permission_denied_is_denied():
    """OUTCOME: google.api_core.exceptions.PermissionDenied → status='denied'."""
    class PermissionDenied(Exception):
        pass
    status, code, _ = classify_cloud_error(PermissionDenied("scope missing"), "gcp")
    assert status == "denied"
    assert code == "PermissionDenied"


def test_gcp_other_error_is_error():
    """OUTCOME: Non-denied GCP errors classify as 'error'."""
    class ServiceUnavailable(Exception):
        pass
    status, _, _ = classify_cloud_error(ServiceUnavailable("503"), "gcp")
    assert status == "error"


def test_oci_403_is_denied():
    """OUTCOME: OCI ServiceError with status=403 → 'denied'."""
    exc = MagicMock()
    exc.status = 403
    exc.code = "Forbidden"
    exc.message = "not authorized"
    status, _, _ = classify_cloud_error(exc, "oci")
    assert status == "denied"


def test_oci_not_authorized_code_is_denied():
    """OUTCOME: OCI code=NotAuthorizedOrNotFound (masked-404 for permission issues) → 'denied'."""
    exc = MagicMock()
    exc.status = 404
    exc.code = "NotAuthorizedOrNotFound"
    exc.message = "hidden"
    status, _, _ = classify_cloud_error(exc, "oci")
    assert status == "denied"


def test_oci_500_is_error():
    """OUTCOME: OCI 500 is 'error', not 'denied'."""
    exc = MagicMock()
    exc.status = 500
    exc.code = "InternalError"
    exc.message = "backend"
    status, _, _ = classify_cloud_error(exc, "oci")
    assert status == "error"


def test_cloud_error_to_result_shape():
    """OUTCOME: to_result preserves extra kwargs and standardizes status/error keys."""
    res = cloud_error_to_result(_aws_client_error("AccessDenied", "no perms"), "aws", instances=[])
    assert res["status"] == "denied"
    assert res["error_code"] == "AccessDenied"
    assert "AccessDenied" in res["error"]
    assert res["instances"] == []


def test_unknown_provider_falls_back_to_error():
    """OUTCOME: Unknown provider strings don't crash — return 'error' generic."""
    status, code, _ = classify_cloud_error(Exception("x"), "somecloud")
    assert status == "error"
    assert code == "Unknown"
