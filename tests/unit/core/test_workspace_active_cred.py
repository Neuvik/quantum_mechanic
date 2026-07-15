"""Tests for workspace active_credential_id identity verification (defense in depth).

The guard compares `principal_id` (a stable identity claim: ARN for AWS,
OID+tenant for Entra, etc.) rather than `friendly_name` (a display alias).
Comparing friendly_name produced false positives — see the regression
guarded by test_use_survives_friendly_name_alias_mismatch_for_aws.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.workspace import CredentialMismatchError, Workspace


def test_active_credential_setter_raises_on_principal_id_mismatch():
    """OUTCOME: When principal_id was captured at import and live whoami returns a
    DIFFERENT principal_id → CredentialMismatchError. This is the actual
    substitution-attempt case the guard exists to catch."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-verify", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="azure",
            credential_type="captured_token",
            secret_data=json.dumps({
                "method": "captured_token",
                "access_token": "fake",
                "expires_on": 9999999999,
                "captured_principal": "alice@example.com",
            }),
            friendly_name="alice@example.com",
            principal_id="alice-oid-1234",
        )

        with patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.whoami") as mock_whoami:
            mock_whoami.return_value = MagicMock(
                friendly_name="impostor@example.com",
                principal_id="impostor-oid-9999",
            )
            with pytest.raises(CredentialMismatchError, match="impostor"):
                ws.active_credential_id = cred_id


def test_active_credential_setter_succeeds_when_principal_id_matches():
    """OUTCOME: matching principal_id → setter succeeds."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-match", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="azure",
            credential_type="captured_token",
            secret_data=json.dumps({
                "method": "captured_token",
                "access_token": "fake",
                "expires_on": 9999999999,
                "captured_principal": "alice@example.com",
            }),
            friendly_name="alice@example.com",
            principal_id="alice-oid-1234",
        )
        with patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.whoami") as mock_whoami:
            mock_whoami.return_value = MagicMock(
                friendly_name="alice@example.com",
                principal_id="alice-oid-1234",
            )
            ws.active_credential_id = cred_id
        assert ws.active_credential_id == cred_id


def test_setting_active_credential_to_none_skips_verification():
    """OUTCOME: clearing active credential (None) doesn't run whoami."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-clear", workspace_dir=Path(td))
        ws.active_credential_id = None  # must not raise; no provider call


def _patch_aws(whoami_result):
    """Return a context manager that mocks both AWSAuthProvider.authenticate
    and .whoami — needed because tests don't have real AWS creds available."""
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch(
        "quantum_mechanic.providers.aws.auth.AWSAuthProvider.authenticate",
        return_value=MagicMock(),
    ))
    stack.enter_context(patch(
        "quantum_mechanic.providers.aws.auth.AWSAuthProvider.whoami",
        return_value=whoami_result,
    ))
    return stack


def test_use_survives_friendly_name_alias_mismatch_for_aws():
    """REGRESSION: `import aws --profile rg_deploy; use 1` was failing because
    the stored friendly_name (`profile:rg_deploy`) doesn't equal the parsed
    ARN principal (`rg_deploy_user`) — but they're two different concepts
    (display alias vs identity claim). The guard must compare principal_id.

    ANTI-GAMIFICATION: If the guard ever falls back to comparing
    friendly_name when principal_id matches, this test fails.
    """
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-aws-regression", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "rg_deploy"}),
            friendly_name="profile:rg_deploy",
            principal_id="arn:aws:iam::123456789012:user/rg_deploy_user",
        )
        who = MagicMock(
            friendly_name="rg_deploy_user",
            principal_id="arn:aws:iam::123456789012:user/rg_deploy_user",
        )
        with _patch_aws(who):
            ws.active_credential_id = cred_id  # must not raise
        assert ws.active_credential_id == cred_id


def test_use_backward_compat_recovers_principal_id_when_missing():
    """OUTCOME: A credential imported without principal_id (pre-fix data) doesn't
    hard-fail on `use`. Instead we auto-capture the principal_id from the live
    whoami so future uses ARE strictly verified.
    """
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-bc", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "old_cred"}),
            friendly_name="profile:old_cred",
            # No principal_id — as if imported before the fix.
        )
        who = MagicMock(
            friendly_name="old_cred_user",
            principal_id="arn:aws:iam::111:user/old_cred_user",
        )
        with _patch_aws(who):
            ws.active_credential_id = cred_id
        cred = ws.get_credential(cred_id)
        assert cred.principal_id == "arn:aws:iam::111:user/old_cred_user"


def test_use_raises_on_principal_id_mismatch_after_backward_compat_recovery():
    """OUTCOME: After a pre-fix cred auto-captures principal_id on first use,
    a subsequent use with a different live identity DOES trigger the guard."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-bc2", workspace_dir=Path(td))
        cred_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "old_cred"}),
            friendly_name="profile:old_cred",
        )
        who_alice = MagicMock(
            friendly_name="alice_user",
            principal_id="arn:aws:iam::111:user/alice_user",
        )
        with _patch_aws(who_alice):
            ws.active_credential_id = cred_id  # recovers principal_id

        who_bob = MagicMock(
            friendly_name="bob_user",
            principal_id="arn:aws:iam::111:user/bob_user",
        )
        with _patch_aws(who_bob):
            with pytest.raises(CredentialMismatchError, match="bob_user"):
                ws.active_credential_id = cred_id
