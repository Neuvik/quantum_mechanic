"""Tests for `use <id>` failure UX — prompt state must roll back."""
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.workspace import CredentialMismatchError
from quantum_mechanic.shell.commands import cmd_use


def test_use_failure_rolls_back_active_credential_id():
    """OUTCOME: When workspace setter raises, state.active_credential_id stays None."""
    state = MagicMock()
    state.transport = MagicMock()
    # transport must return a credential with id=2 so cmd_use reaches the setter
    state.transport.list_credentials.return_value = [
        {"id": 2, "provider": "aws", "friendly_name": "test-cred", "credential_type": "static"}
    ]
    state.workspace = MagicMock()
    state.active_credential_id = None
    # The workspace setter raises
    type(state.workspace).active_credential_id = property(
        lambda self: None,
        lambda self, v: (_ for _ in ()).throw(CredentialMismatchError("identity mismatch")),
    )
    with patch("quantum_mechanic.shell.commands.console"):
        cmd_use(state, ["2"])
    # state.active_credential_id must remain None — prompt won't show [cred:2]
    assert state.active_credential_id is None
