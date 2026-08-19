# ================================================================
# TESTS: ARM pivot — cross-provider technique dispatch (AQH-11)
# ----------------------------------------------------------------
# Verifies the full pivot chain:
#   EntraTokenStore (FOCI refresh token)
#     → foci_expand(ARM)
#     → extra_providers=["azure"]
#     → technique with providers=["azure"] runs with ctx.provider_name="azure"
#     → EntraTokenCredential bridges token into Azure SDK contract
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueRunner
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.azure.auth import AzureAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry
from quantum_mechanic.providers.entra.auth import EntraAuthProvider
from quantum_mechanic.providers.entra.token_store import ARM, EntraToken, EntraTokenStore
from quantum_mechanic.providers.gcp.auth import GCPAuthProvider
from quantum_mechanic.providers.oci.auth import OCIAuthProvider


def _build_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register(AWSAuthProvider())
    registry.register(AzureAuthProvider())
    registry.register(EntraAuthProvider())
    registry.register(GCPAuthProvider())
    registry.register(OCIAuthProvider())
    return registry


def _make_entra_cred(workspace: Workspace) -> int:
    """Store an Entra credential with a FOCI refresh token and return its ID."""
    import json

    store = EntraTokenStore(tenant_id="tenant-test", user_upn="pivot@test.example")
    foci_rt = EntraToken(
        token_type="refresh_token",
        resource="",
        value="foci-refresh-token-value",
        tenant_id="tenant-test",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=True,
    )
    store.add_token(foci_rt)

    cred_id = workspace.add_credential(
        provider="entra",
        credential_type="token_store",
        secret_data=json.dumps({"token_store": store.to_dict()}),
        friendly_name="entra:pivot@test.example",
    )
    return cred_id


def _make_entra_cred_with_arm(workspace: Workspace) -> int:
    """Store an Entra credential with a valid ARM access token and return its ID."""
    import json

    store = EntraTokenStore(tenant_id="tenant-test", user_upn="pivot@test.example")
    arm_token = EntraToken(
        token_type="access_token",
        resource=ARM,
        value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0ZW5hbnQtdGVzdCJ9.sig",
        tenant_id="tenant-test",
        client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
        foci=False,
    )
    store.add_token(arm_token)

    cred_id = workspace.add_credential(
        provider="entra",
        credential_type="token_store",
        secret_data=json.dumps({"token_store": store.to_dict()}),
        friendly_name="entra:pivot@test.example",
    )
    return cred_id


@pytest.fixture
def workspace(tmp_path):
    ws = Workspace.create("pivot-test", tmp_path)
    return ws


class TestARMPivotDispatch:
    """The runner routes azure techniques to ctx.provider_name='azure' via extra_providers."""

    def test_azure_technique_visible_via_extra_providers(self, workspace):
        """With extra_providers=["azure"], enum_compute resolves to azure dispatch."""
        loader = TechniqueLoader()
        loader.load_all()
        runner = TechniqueRunner(workspace, loader, _build_registry())

        cred_id = _make_entra_cred(workspace)

        # Provide a fake ARM token via foci_expand mock
        arm_token = EntraToken(
            token_type="access_token",
            resource=ARM,
            value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0ZW5hbnQtdGVzdCJ9.sig",
            tenant_id="tenant-test",
            client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
            foci=False,
        )

        azure_mock = MagicMock()
        azure_mock.return_value.subscriptions.list.return_value = []

        with patch(
            "quantum_mechanic.providers.entra.foci.foci_expand",
            return_value=arm_token,
        ), patch.dict("sys.modules", {
            "azure.mgmt.compute": MagicMock(),
            "azure.mgmt.network": MagicMock(),
            "azure.mgmt.subscription": azure_mock,
        }):
            result = runner.run(
                "discovery/enum_compute",
                credential_id=cred_id,
                params={},
                extra_providers=["azure"],
            )

        # Result should come from azure dispatch, not return a provider-not-implemented error
        assert result.status == "success"
        assert result.provider == "azure"
        assert "instances" in result.data

    def test_effective_provider_is_azure_not_entra(self, workspace):
        """result.provider must be 'azure' when running azure technique via ARM pivot."""
        loader = TechniqueLoader()
        loader.load_all()
        runner = TechniqueRunner(workspace, loader, _build_registry())
        cred_id = _make_entra_cred(workspace)

        arm_token = EntraToken(
            token_type="access_token",
            resource=ARM,
            value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0ZW5hbnQtdGVzdCJ9.sig",
            tenant_id="tenant-test",
            client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
            foci=False,
        )

        with patch(
            "quantum_mechanic.providers.entra.foci.foci_expand",
            return_value=arm_token,
        ), patch.dict("sys.modules", {
            "azure.mgmt.compute": MagicMock(),
            "azure.mgmt.network": MagicMock(),
            "azure.mgmt.subscription": MagicMock(),
        }):
            result = runner.run(
                "discovery/enum_compute",
                credential_id=cred_id,
                params={},
                extra_providers=["azure"],
            )

        assert result.provider == "azure", (
            f"Expected result.provider='azure', got '{result.provider}'"
        )


class TestARMTokenAutoRestore:
    """_try_restore_arm_pivot sets _extra_providers when ARM token is present."""

    def test_arm_token_in_store_unlocks_azure_techniques(self, workspace):
        from quantum_mechanic.shell.commands import ShellState, _try_restore_arm_pivot

        cred_id = _make_entra_cred_with_arm(workspace)

        state = ShellState(workspace=workspace)
        state.active_credential_id = cred_id

        _try_restore_arm_pivot(state)

        assert state._extra_providers == ["azure"], (
            "_try_restore_arm_pivot should set _extra_providers=['azure'] when ARM token present"
        )

    def test_no_arm_token_leaves_extra_providers_empty(self, workspace):
        from quantum_mechanic.shell.commands import ShellState, _try_restore_arm_pivot

        cred_id = _make_entra_cred(workspace)  # FOCI only, no ARM token

        state = ShellState(workspace=workspace)
        state.active_credential_id = cred_id

        _try_restore_arm_pivot(state)

        assert state._extra_providers == []
