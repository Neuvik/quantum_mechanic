"""Tests for workspace active_credential_id identity verification (defense in depth)."""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.workspace import CredentialMismatchError, Workspace


def test_active_credential_setter_verifies_identity():
    """OUTCOME: setting active_credential_id triggers whoami; mismatch raises."""
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
        )

        # When provider.whoami returns a different identity, setter MUST raise.
        with patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.whoami") as mock_whoami:
            mock_whoami.return_value = MagicMock(friendly_name="impostor@example.com")
            with pytest.raises(CredentialMismatchError, match="impostor"):
                ws.active_credential_id = cred_id


def test_active_credential_setter_succeeds_when_identity_matches():
    """OUTCOME: matching identity → setter succeeds, no exception."""
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
        )

        with patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.whoami") as mock_whoami:
            mock_whoami.return_value = MagicMock(friendly_name="alice@example.com")
            ws.active_credential_id = cred_id  # must not raise

        assert ws.active_credential_id == cred_id


def test_setting_active_credential_to_none_skips_verification():
    """OUTCOME: clearing active credential (None) doesn't run whoami."""
    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("test-clear", workspace_dir=Path(td))
        ws.active_credential_id = None  # must not raise; no provider call
