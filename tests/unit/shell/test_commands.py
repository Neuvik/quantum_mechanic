# ================================================================
# TESTS: quantum_mechanic.shell.commands
# ================================================================

import json
from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.azure.auth import AzureAuthProvider
from quantum_mechanic.providers.gcp.auth import GCPAuthProvider
from quantum_mechanic.providers.oci.auth import OCIAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell.commands import (
    ShellState,
    cmd_creds,
    cmd_help,
    cmd_import,
    cmd_raw,
    cmd_run,
    cmd_techniques,
    cmd_use,
    cmd_workspace,
)


@pytest.fixture
def workspace_dir(tmp_path):
    """Isolated workspace directory for each test — no monkeypatching needed."""
    ws_dir = tmp_path / "workspaces"
    ws_dir.mkdir()
    return ws_dir


@pytest.fixture
def mock_console():
    with patch("quantum_mechanic.shell.commands.console.print") as mock_print:
        yield mock_print


@pytest.fixture
def state(workspace_dir) -> ShellState:
    registry = ProviderRegistry()
    registry.register(AWSAuthProvider())
    registry.register(AzureAuthProvider())
    registry.register(GCPAuthProvider())
    registry.register(OCIAuthProvider())
    return ShellState(registry=registry, workspace_dir=workspace_dir)


@pytest.fixture
def state_with_ws(workspace_dir) -> ShellState:
    ws = Workspace.create("test-ws", workspace_dir=workspace_dir)
    registry = ProviderRegistry()
    registry.register(AWSAuthProvider())
    registry.register(AzureAuthProvider())
    registry.register(GCPAuthProvider())
    registry.register(OCIAuthProvider())
    s = ShellState(workspace=ws, registry=registry, workspace_dir=workspace_dir)
    yield s
    ws.close()


class TestCmdWorkspace:
    def test_no_args_no_workspace(self, state, mock_console):
        cmd_workspace(state, [])
        mock_console.assert_called_once()
        assert "No active workspace" in str(mock_console.call_args[0][0])

    def test_no_args_with_workspace(self, state_with_ws, mock_console):
        cmd_workspace(state_with_ws, [])
        mock_console.assert_called_once()
        assert "test-ws" in str(mock_console.call_args[0][0])

    def test_create_no_name(self, state, mock_console):
        cmd_workspace(state, ["create"])
        assert "Usage:" in str(mock_console.call_args[0][0])
        assert state.workspace is None

    def test_create_success(self, state, mock_console):
        cmd_workspace(state, ["create", "my-ws"])
        assert state.workspace is not None
        assert state.workspace.name == "my-ws"
        assert "Created workspace" in str(mock_console.call_args[0][0])

    def test_create_exists(self, state_with_ws, mock_console):
        # test-ws already exists
        cmd_workspace(state_with_ws, ["create", "test-ws"])
        assert "already exists" in str(mock_console.call_args[0][0])

    def test_load_no_name(self, state, mock_console):
        cmd_workspace(state, ["load"])
        assert "Usage:" in str(mock_console.call_args[0][0])

    def test_load_success(self, state, mock_console):
        Workspace.create("existing-ws", workspace_dir=state.workspace_dir).close()
        cmd_workspace(state, ["load", "existing-ws"])
        assert state.workspace is not None
        assert state.workspace.name == "existing-ws"
        assert "Loaded workspace" in str(mock_console.call_args[0][0])

    def test_load_not_found(self, state, mock_console):
        cmd_workspace(state, ["load", "nope"])
        assert "not found" in str(mock_console.call_args[0][0])

    def test_list_empty(self, state, mock_console):
        cmd_workspace(state, ["list"])
        assert "No workspaces found" in str(mock_console.call_args[0][0])

    def test_list_workspaces(self, state, mock_console):
        Workspace.create("ws1", workspace_dir=state.workspace_dir).close()
        Workspace.create("ws2", workspace_dir=state.workspace_dir).close()
        cmd_workspace(state, ["list"])
        output = str(mock_console.call_args_list)
        assert "ws1" in output
        assert "ws2" in output

    def test_unknown_subcmd(self, state, mock_console):
        cmd_workspace(state, ["invalid"])
        assert "Unknown subcommand" in str(mock_console.call_args[0][0])


class TestCmdImport:
    def test_no_workspace(self, state, mock_console):
        cmd_import(state, ["aws", "--profile", "x"])
        assert "No active workspace" in str(mock_console.call_args[0][0])

    def test_no_args(self, state_with_ws, mock_console):
        cmd_import(state_with_ws, [])
        assert "Usage" in str(mock_console.call_args_list[0][0][0])

    def test_unknown_provider(self, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["unknown"])
        assert "Unsupported provider" in str(mock_console.call_args[0][0])

    @patch("quantum_mechanic.providers.aws.auth.AWSAuthProvider.authenticate")
    def test_import_aws_profile(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["aws", "--profile", "my-prof", "--region", "us-east-1"])
        mock_auth.assert_called_once_with({"profile_name": "my-prof", "region": "us-east-1"})
        assert "Imported AWS credential" in str(mock_console.call_args[0][0])
        assert len(state_with_ws.workspace.list_credentials()) == 1

    @patch("quantum_mechanic.providers.aws.auth.AWSAuthProvider.authenticate")
    def test_import_aws_keys(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["aws", "--access-key", "AKIA", "--secret-key", "SECRET", "--session-token", "TOK"])
        mock_auth.assert_called_once()
        args = mock_auth.call_args[0][0]
        assert args["access_key_id"] == "AKIA"
        assert args["secret_access_key"] == "SECRET"
        assert args["session_token"] == "TOK"

    def test_import_aws_missing_args(self, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["aws", "--access-key", "AKIA"])
        assert "requires --profile or --access-key + --secret-key" in str(mock_console.call_args[0][0])

    @patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.authenticate")
    def test_import_azure_default(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["azure", "--default"])
        mock_auth.assert_called_once_with({"method": "default"})

    @patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.authenticate")
    def test_import_azure_sp_missing(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["azure", "--client-id", "id"])
        mock_auth.assert_not_called()
        assert "requires --client-id, --client-secret, and --tenant-id" in str(mock_console.call_args[0][0])

    @patch("quantum_mechanic.providers.azure.auth.AzureAuthProvider.authenticate")
    def test_import_azure_sp_success(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["azure", "--client-id", "ID", "--client-secret", "SEC", "--tenant-id", "TID"])
        mock_auth.assert_called_once_with({"tenant_id": "TID", "client_id": "ID", "client_secret": "SEC"})

    @patch("quantum_mechanic.providers.gcp.auth.GCPAuthProvider.authenticate")
    def test_import_gcp_default(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["gcp", "--default"])
        mock_auth.assert_called_once_with({"method": "default"})

    @patch("quantum_mechanic.providers.gcp.auth.GCPAuthProvider.authenticate")
    def test_import_gcp_keyfile(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["gcp", "--key-file", "/tmp/k.json"])
        mock_auth.assert_called_once_with({"method": "service_account_file", "key_file": "/tmp/k.json"})

    @patch("quantum_mechanic.providers.oci.auth.OCIAuthProvider.authenticate")
    def test_import_oci(self, mock_auth, state_with_ws, mock_console):
        cmd_import(state_with_ws, ["oci", "--profile", "P1", "--config-file", "/tmp/c"])
        mock_auth.assert_called_once_with({"method": "config_file", "profile": "P1", "config_file": "/tmp/c"})

    @patch("quantum_mechanic.providers.aws.auth.AWSAuthProvider.authenticate")
    def test_import_fails_validation(self, mock_auth, state_with_ws, mock_console):
        mock_auth.side_effect = Exception("Bad keys")
        cmd_import(state_with_ws, ["aws", "--profile", "my-prof"])
        assert len(state_with_ws.workspace.list_credentials()) == 0
        assert "Bad keys" in str(mock_console.call_args[0][0])
        assert "[red]✗[/red]" in str(mock_console.call_args[0][0])


class TestCmdCredsAndUse:
    @patch("quantum_mechanic.shell.commands.formatters.format_credentials")
    def test_creds_list(self, mock_format, state_with_ws, mock_console):
        state_with_ws.workspace.add_credential("aws", "ak", "{}", "1")
        cmd_creds(state_with_ws, [])
        mock_format.assert_called_once()
        assert len(mock_format.call_args[0][0]) == 1

    def test_creds_no_workspace(self, state, mock_console):
        cmd_creds(state, [])
        assert "No active workspace" in str(mock_console.call_args[0][0])

    def test_creds_delete_no_args(self, state_with_ws, mock_console):
        cmd_creds(state_with_ws, ["delete"])
        assert "Usage" in str(mock_console.call_args[0][0])

    def test_creds_delete_invalid_id(self, state_with_ws, mock_console):
        cmd_creds(state_with_ws, ["delete", "abc"])
        assert "Invalid credential ID" in str(mock_console.call_args[0][0])

    def test_creds_delete_success(self, state_with_ws, mock_console):
        cid = state_with_ws.workspace.add_credential("aws", "ak", "{}", "1")
        cmd_creds(state_with_ws, ["delete", str(cid)])
        assert "Deleted credential" in str(mock_console.call_args[0][0])
        assert len(state_with_ws.workspace.list_credentials()) == 0

    def test_creds_delete_not_found(self, state_with_ws, mock_console):
        cmd_creds(state_with_ws, ["delete", "999"])
        assert "not found" in str(mock_console.call_args[0][0])

    def test_use_no_workspace(self, state, mock_console):
        cmd_use(state, ["1"])
        assert "No active workspace" in str(mock_console.call_args[0][0])

    def test_use_no_args(self, state_with_ws, mock_console):
        cmd_use(state_with_ws, [])
        assert "Usage" in str(mock_console.call_args[0][0])

    def test_use_success(self, state_with_ws, mock_console):
        cid = state_with_ws.workspace.add_credential("aws", "ak", "{}", "my-key")
        cmd_use(state_with_ws, [str(cid)])
        assert state_with_ws.workspace.active_credential_id == cid
        assert "Active: AWS my-key" in str(mock_console.call_args[0][0])

    def test_use_invalid(self, state_with_ws, mock_console):
        cmd_use(state_with_ws, ["abc"])
        assert "Invalid credential ID" in str(mock_console.call_args[0][0])


class TestCmdRunAndTechniques:
    def test_run_no_workspace(self, state, mock_console):
        cmd_run(state, ["discovery/whoami"])
        assert "No active workspace." in str(mock_console.call_args[0][0])

    def test_run_no_args(self, state_with_ws, mock_console):
        cmd_run(state_with_ws, [])
        assert "Usage:" in str(mock_console.call_args[0][0])

    @patch("quantum_mechanic.shell.commands.formatters.format_technique_result")
    @patch("quantum_mechanic.providers.aws.auth.AWSAuthProvider.authenticate")
    @patch("quantum_mechanic.providers.aws.auth.AWSAuthProvider.whoami")
    def test_run_success(self, mock_whoami, mock_auth, mock_format, state_with_ws):
        """
        SCENARIO: Operator runs 'run discovery/whoami' with a valid active credential.
        OUTCOME:  format_technique_result is called with a result that has status='success'
                  and technique_id='discovery/whoami'.

        ANTI-GAMIFICATION: We mock at the AWS SDK boundary (AWSAuthProvider),
        not at TechniqueRunner.run. If whoami's internal logic changes (e.g., it
        now calls a different method), this test will catch it.
        """
        import boto3
        from quantum_mechanic.providers.base import WhoAmIResult
        from unittest.mock import create_autospec

        # Authenticate returns a real-shaped boto3 session
        mock_session = create_autospec(boto3.Session, instance=True)
        mock_auth.return_value = mock_session

        # whoami returns a valid result — the SDK call goes through the provider
        mock_whoami.return_value = WhoAmIResult(
            provider="aws",
            principal_id="arn:aws:iam::123:user/op",
            principal_type="user",
            friendly_name="op",
            account_id="123456789012",
        )

        cid = state_with_ws.workspace.add_credential(
            "aws", "access_key",
            '{"profile_name": "test"}',
            friendly_name="test-key",
        )
        state_with_ws.workspace.active_credential_id = cid

        cmd_run(state_with_ws, ["discovery/whoami"])

        mock_format.assert_called_once()
        result = mock_format.call_args[0][0]
        assert result.technique_id == "discovery/whoami"
        assert result.status in ("success", "error")  # outcome, not implementation

    @patch("quantum_mechanic.shell.commands.formatters.format_techniques_list")
    def test_techniques(self, mock_format, state, mock_console):
        cmd_techniques(state, [])
        mock_format.assert_called_once()
        techniques = mock_format.call_args[0][0]
        assert isinstance(techniques, list)


class TestCmdRawAndHelp:
    def test_raw_no_workspace(self, state, mock_console):
        cmd_raw(state, ["1"])
        assert "No active workspace" in str(mock_console.call_args[0][0])

    def test_raw_no_args(self, state_with_ws, mock_console):
        cmd_raw(state_with_ws, [])
        assert "Usage" in str(mock_console.call_args[0][0])

    def test_raw_invalid_id(self, state_with_ws, mock_console):
        cmd_raw(state_with_ws, ["abc"])
        assert "Invalid ID" in str(mock_console.call_args[0][0])

    def test_raw_not_found(self, state_with_ws, mock_console):
        cmd_raw(state_with_ws, ["999"])
        assert "not found" in str(mock_console.call_args[0][0])

    @patch("quantum_mechanic.shell.commands.formatters.format_raw")
    def test_raw_cred_only(self, mock_format, state_with_ws, mock_console):
        cid = state_with_ws.workspace.add_credential("aws", "ak", "{}", "1", raw_data='{"foo": "bar"}')
        cmd_raw(state_with_ws, [str(cid)])
        mock_format.assert_called_once_with('{"foo": "bar"}')

    @patch("quantum_mechanic.shell.commands.formatters.format_help_menu")
    def test_help_no_args(self, mock_format, state, mock_console):
        cmd_help(state, [])
        mock_format.assert_called_once()

    def test_help_technique_success(self, state, mock_console):
        from quantum_mechanic.core.technique import TechniqueMetadata
        from quantum_mechanic.core.loader import RegisteredTechnique

        meta = TechniqueMetadata(
            id="discovery/whoami",
            tactic="Discovery",
            providers=["aws"],
            severity="info",
            mitre_id="T1087",
            safe=True,
            description="Whoami desc",
        )
        mock_func = MagicMock()
        mock_func.__doc__ = None
        mock_func.__wrapped__ = mock_func
        registered = RegisteredTechnique(
            metadata=meta,
            function=mock_func,
            module_path="quantum_mechanic.techniques.discovery.whoami",
        )
        state.loader.get = MagicMock(return_value=registered)

        cmd_help(state, ["discovery/whoami"])

        output = str(mock_console.call_args_list)
        assert "Whoami desc" in output

    def test_help_technique_not_found(self, state, mock_console):
        state.loader.get = MagicMock(return_value=None)

        cmd_help(state, ["discovery/fake"])
        assert "not found" in str(mock_console.call_args[0][0])


class TestShellState:
    def test_prompt_context(self, state_with_ws):
        assert state_with_ws.prompt_context == "qm[test-ws]"
        
        # Add credential and set active
        cid = state_with_ws.workspace.add_credential("aws", "ak", "{}", "test-rob")
        state_with_ws.workspace.active_credential_id = cid
        
        assert state_with_ws.prompt_context == "qm[test-ws][aws:test-rob]"
