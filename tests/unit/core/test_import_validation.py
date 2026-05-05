# ================================================================
# TESTS: quantum_mechanic.shell.commands — credential import
# ----------------------------------------------------------------
# WHAT:   Tests that the import command validates credentials
#         BEFORE storing them. If authentication fails, nothing
#         should be written to the database.
#
# WHY:    Without validation, 'import gcp --default' on a machine
#         with no GCP credentials silently stores a phantom entry.
#         The operator thinks they have a cred loaded when they
#         don't. This test suite proves the gate works.
# ================================================================

import json
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.shell.commands import (
    ShellState,
    _validate_and_import,
)


@pytest.fixture
def shell_state(tmp_path):
    """Build a ShellState with a real workspace and a mocked registry."""
    ws = Workspace.create("import-test", tmp_path)
    registry = ProviderRegistry()

    # --------------------------------------------------------
    # Create mock providers for all 4 clouds.
    # Each has authenticate() that can be configured to
    # succeed or fail per test.
    # --------------------------------------------------------
    for name in ("aws", "azure", "gcp", "oci"):
        mock_provider = MagicMock()
        mock_provider.provider_name = name
        mock_provider.authenticate.return_value = MagicMock()
        registry.register(mock_provider)

    state = ShellState(
        workspace=ws,
        loader=TechniqueLoader(),
        registry=registry,
    )
    yield state
    ws.close()


class TestValidateAndImport:
    """Test the _validate_and_import gate function."""

    def test_valid_creds_are_stored(self, shell_state):
        """When authenticate() succeeds, credential is stored."""
        _validate_and_import(
            shell_state,
            provider="aws",
            credential_type="access_key",
            secret={"profile_name": "test"},
            friendly="profile:test",
        )
        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 1
        assert creds[0].provider == "aws"
        assert creds[0].friendly_name == "profile:test"

    def test_invalid_creds_are_rejected(self, shell_state):
        """When authenticate() raises, nothing is stored."""
        # --------------------------------------------------------
        # Make the GCP provider's authenticate() raise an error
        # simulating missing Application Default Credentials.
        # --------------------------------------------------------
        gcp_provider = shell_state.registry.get("gcp")
        gcp_provider.authenticate.side_effect = Exception(
            "Could not automatically determine credentials"
        )

        _validate_and_import(
            shell_state,
            provider="gcp",
            credential_type="service_account",
            secret={"method": "default"},
            friendly="ApplicationDefaultCredentials",
        )
        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 0

    def test_invalid_oci_not_stored(self, shell_state):
        """OCI config file not found does not store credential."""
        oci_provider = shell_state.registry.get("oci")
        oci_provider.authenticate.side_effect = FileNotFoundError(
            "Config file ~/.oci/config not found"
        )

        _validate_and_import(
            shell_state,
            provider="oci",
            credential_type="api_key",
            secret={"method": "config_file", "profile": "DEFAULT"},
            friendly="config:DEFAULT",
        )
        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 0

    def test_authenticate_is_called_with_secret(self, shell_state):
        """The provider's authenticate() receives the exact secret dict."""
        secret = {"profile_name": "sa_key1", "region": "us-west-2"}
        _validate_and_import(
            shell_state,
            provider="aws",
            credential_type="access_key",
            secret=secret,
            friendly="profile:sa_key1",
        )
        aws_provider = shell_state.registry.get("aws")
        aws_provider.authenticate.assert_called_once_with(secret)

    def test_multiple_valid_imports(self, shell_state):
        """Multiple valid imports create multiple credentials."""
        _validate_and_import(
            shell_state,
            "aws",
            "access_key",
            {"profile_name": "prod"},
            "profile:prod",
        )
        _validate_and_import(
            shell_state,
            "azure",
            "access_key",
            {"method": "default"},
            "DefaultAzureCredential",
        )

        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 2
        providers = {c.provider for c in creds}
        assert providers == {"aws", "azure"}

    def test_mixed_valid_and_invalid(self, shell_state):
        """Only valid imports are stored; invalid ones are skipped."""
        # --------------------------------------------------------
        # AWS succeeds, GCP fails — only AWS should be stored.
        # --------------------------------------------------------
        gcp_provider = shell_state.registry.get("gcp")
        gcp_provider.authenticate.side_effect = Exception("no creds")

        _validate_and_import(
            shell_state,
            "aws",
            "access_key",
            {"profile_name": "good"},
            "profile:good",
        )
        _validate_and_import(
            shell_state,
            "gcp",
            "service_account",
            {"method": "default"},
            "ADC",
        )

        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 1
        assert creds[0].provider == "aws"

    def test_unknown_provider_rejected(self, shell_state):
        """Import for a provider not in the registry is rejected."""
        _validate_and_import(
            shell_state,
            "digitalocean",
            "token",
            {"token": "fake"},
            "do-token",
        )
        creds = shell_state.workspace.list_credentials()
        assert len(creds) == 0

    def test_secret_data_stored_correctly(self, shell_state):
        """The stored secret_data matches what was passed in."""
        secret = {"profile_name": "myprofile", "region": "eu-west-1"}
        _validate_and_import(
            shell_state,
            "aws",
            "access_key",
            secret,
            "profile:myprofile",
        )
        stored = shell_state.workspace.get_credential_secret(1)
        assert json.loads(stored) == secret
