from __future__ import annotations

from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands_entra import acquire_entra


def _fake_token() -> dict[str, object]:
    return {
        "access_token": "eyJ.fake.access",
        "refresh_token": "0.fake.refresh",
        "expires_in": 3600,
        "token_type": "Bearer",
    }


def test_acquire_entra_interactive_accepts_explicit_scope():
    """OUTCOME: --scope passes a single delegated permission into the interactive flow."""
    state = MagicMock()
    state.workspace = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize",
        return_value=_fake_token(),
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra._preflight_scope_request",
        return_value=True,
    ), patch(
        "quantum_mechanic.shell.commands_entra._store_from_response",
        return_value=MagicMock(),
    ), patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=1,
    ), patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ), patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        acquire_entra(state, ["interactive", "--scope", "RoleManagement.Read.Directory"])

    assert mock_authorize.call_args.kwargs["scopes"] == ["RoleManagement.Read.Directory"]


def test_acquire_entra_device_code_accepts_named_bundle():
    """OUTCOME: --bundle resolves before calling initiate_device_code / poll_device_code."""
    state = MagicMock()
    state.workspace = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.initiate_device_code",
        return_value={
            "device_code": "dev",
            "user_code": "ABCD-1234",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
        },
    ) as mock_initiate, patch(
        "quantum_mechanic.providers.entra.exchange.poll_device_code",
        return_value=_fake_token(),
    ) as mock_poll, patch(
        "quantum_mechanic.shell.commands_entra._preflight_scope_request",
        return_value=True,
    ), patch(
        "quantum_mechanic.shell.commands_entra._store_from_response",
        return_value=MagicMock(),
    ), patch(
        "quantum_mechanic.shell.commands_entra._persist_store",
        return_value=1,
    ), patch(
        "quantum_mechanic.shell.commands_entra._set_active"
    ), patch(
        "quantum_mechanic.shell.commands_entra._print_import_summary"
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ):
        acquire_entra(state, ["device_code", "--bundle", "pim-read"])

    expected = [
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
    ]
    assert mock_initiate.call_args.kwargs["scopes"] == expected
    assert mock_poll.call_args.kwargs["scopes"] == expected


def test_acquire_entra_rejects_scope_and_bundle_together():
    """OUTCOME: mutually-exclusive flags fail cleanly and do not hit the network path."""
    state = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize"
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra.console"
    ) as mock_console:
        acquire_entra(
            state,
            [
                "interactive",
                "--scope",
                "User.Read",
                "--bundle",
                "pim-read",
            ],
        )

    mock_authorize.assert_not_called()
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "bundle" in printed.lower()
    assert "scope" in printed.lower()


def test_acquire_entra_rejects_unknown_bundle():
    """OUTCOME: invalid bundle names are surfaced to the operator immediately."""
    state = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize"
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra.console"
    ) as mock_console:
        acquire_entra(state, ["interactive", "--bundle", "not-real"])

    mock_authorize.assert_not_called()
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "unknown bundle" in printed.lower()
    assert "not-real" in printed


def test_acquire_entra_interactive_rejects_client_without_bundle_compatibility():
    """OUTCOME: QM fails locally before opening a browser when the selected
    first-party client cannot request the bundle's delegated scopes."""
    state = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.interactive_authorize"
    ) as mock_authorize, patch(
        "quantum_mechanic.shell.commands_entra._client_scope_compatibility",
        return_value=(False, ["RoleEligibilitySchedule.Read.Directory"]),
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ) as mock_console:
        acquire_entra(
            state,
            ["interactive", "--client", "vs-legacy", "--bundle", "pim-read"],
        )

    mock_authorize.assert_not_called()
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "cannot request" in printed.lower()
    assert "RoleEligibilitySchedule.Read.Directory" in printed
    assert "browserdump" in printed or "custom app" in printed.lower()


def test_acquire_entra_device_code_rejects_client_without_scope_compatibility():
    """OUTCOME: device_code gets the same preflight block for impossible
    delegated scope requests."""
    state = MagicMock()

    with patch(
        "quantum_mechanic.providers.entra.exchange.initiate_device_code"
    ) as mock_initiate, patch(
        "quantum_mechanic.shell.commands_entra._client_scope_compatibility",
        return_value=(False, ["RoleAssignmentSchedule.Read.Directory"]),
    ), patch(
        "quantum_mechanic.shell.commands_entra.console"
    ) as mock_console:
        acquire_entra(
            state,
            ["device_code", "--client", "office", "--scope", "RoleAssignmentSchedule.Read.Directory"],
        )

    mock_initiate.assert_not_called()
    printed = " ".join(str(c) for c in mock_console.print.call_args_list)
    assert "cannot request" in printed.lower()
    assert "RoleAssignmentSchedule.Read.Directory" in printed
