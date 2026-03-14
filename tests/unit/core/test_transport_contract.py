# ================================================================
# TESTS: quantum_mechanic.core.transport (CONTRACT TESTS)
# ----------------------------------------------------------------
# WHAT:  Defines the behaviour contract for all Transport
#        implementations. Both LocalTransport and RemoteTransport
#        must pass every test in this file.
#
# ANTI-GAMIFICATION RULES:
#   - We do NOT mock TechniqueRunner internals.
#   - We do NOT assert which internal methods were called.
#   - We mock at the provider SDK boundary (boto3 / Azure / GCP).
#   - Every test asserts a REAL OUTCOME the operator cares about.
#   - Tests must be capable of failing on real bugs.
#
# TDD STATUS: RED — Transport does not exist yet.
#             These tests define the implementation contract.
#             They will pass once core/transport.py is written.
#
# LAYERS:
#   Layer 1 — Contract (this file): same tests, both transports
#   Layer 4 — Security:             auth enforcement, abuse cases
#   Layer 5 — Chaos:                disconnects, timeouts, retries
# ================================================================

from __future__ import annotations

import json
from unittest.mock import MagicMock, create_autospec, patch

import pytest

# These imports will FAIL until transport.py is written.
# That is intentional. Tests first.
from quantum_mechanic.core.transport import LocalTransport, Transport
from quantum_mechanic.core.runner import TechniqueResult
from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.technique import TechniqueMetadata
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry, WhoAmIResult


# ================================================================
# FIXTURES
# ================================================================

@pytest.fixture
def workspace(tmp_path):
    """Real workspace with one valid AWS credential."""
    ws = Workspace.create("transport-test", tmp_path)
    ws.add_credential(
        provider="aws",
        credential_type="access_key",
        secret_data=json.dumps({"profile_name": "test"}),
        friendly_name="test-key",
    )
    ws.active_credential_id = 1
    yield ws
    ws.close()


@pytest.fixture
def empty_workspace(tmp_path):
    """Workspace with no credentials."""
    ws = Workspace.create("transport-empty", tmp_path)
    yield ws
    ws.close()


@pytest.fixture
def mock_aws_registry():
    """
    Provider registry with a mock AWS provider.

    ANTI-GAMIFICATION: The mock is spec'd against AWSAuthProvider.
    Calling .get() on it instead of .client() will raise AttributeError
    just as the real object would. We are not hiding type bugs.
    """
    registry = ProviderRegistry()

    mock_aws = create_autospec(AWSAuthProvider, instance=True)
    mock_aws.provider_name = "aws"

    # authenticate() returns a spec'd boto3 Session, not a bare MagicMock.
    # This ensures technique code that calls .get() instead of .client()
    # fails immediately — catches the real class of bugs we've seen before.
    import boto3
    mock_session = create_autospec(boto3.Session, instance=True)
    mock_aws.authenticate.return_value = mock_session

    # whoami() returns the real WhoAmIResult shape.
    mock_aws.whoami.return_value = WhoAmIResult(
        provider="aws",
        principal_id="arn:aws:iam::123456789012:user/test-operator",
        principal_type="user",
        friendly_name="test-operator",
        account_id="123456789012",
    )

    registry.register(mock_aws)
    return registry


@pytest.fixture
def loader():
    """Real technique loader — loads all installed techniques."""
    ldr = TechniqueLoader()
    ldr.load_all()
    return ldr


@pytest.fixture
def local_transport(workspace, loader, mock_aws_registry):
    """LocalTransport — the in-process implementation."""
    return LocalTransport(workspace, loader, mock_aws_registry)


# ================================================================
# MODULE STRUCTURE: Transport is an ABC
# ================================================================

class TestTransportIsAbstract:
    """
    SCENARIO: Someone tries to instantiate Transport directly.
    OUTCOME:  It raises TypeError — can't instantiate abstract class.
    """

    def test_transport_cannot_be_instantiated_directly(self):
        """Transport ABC must enforce implementation of all methods."""
        with pytest.raises(TypeError):
            Transport()  # type: ignore[abstract]

    def test_local_transport_is_a_transport(self, local_transport):
        """LocalTransport must satisfy the Transport interface."""
        assert isinstance(local_transport, Transport)


# ================================================================
# CONTRACT: run_technique
# ================================================================

class TestRunTechniqueContract:
    """
    Core contract for run_technique across both transport implementations.

    SCENARIO: Operator runs a technique that QM knows about.
    OUTCOME:  A TechniqueResult is returned, identified by the technique
              that ran, with a deterministic status field.
    """

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_known_technique_returns_technique_result(self, request, transport_fixture):
        """
        OUTCOME: run_technique returns TechniqueResult, not an exception.

        Any exception escaping run_technique is a bug — the result contract
        requires errors to be returned as TechniqueResult(status='error'),
        never raised.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("discovery/whoami", credential_id=1)

        assert isinstance(result, TechniqueResult)

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_result_technique_id_matches_what_was_requested(self, request, transport_fixture):
        """
        OUTCOME: The result names the technique that ran.

        An operator reading the timeline must know which technique
        produced each result. If technique_id is wrong, the engagement
        record is corrupted.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("discovery/whoami", credential_id=1)

        assert result.technique_id == "discovery/whoami"

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_result_status_is_one_of_the_valid_states(self, request, transport_fixture):
        """
        OUTCOME: Status is a known value — never free-form noise.

        Downstream systems (timeline, agent decision loop) branch on
        status. An unexpected value breaks the engagement record.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("discovery/whoami", credential_id=1)

        assert result.status in ("success", "error", "skipped"), (
            f"Unknown status '{result.status}' — add it to the contract if intentional."
        )

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_unknown_technique_returns_error_result_not_exception(self, request, transport_fixture):
        """
        SCENARIO: Operator mistypes a technique ID.
        OUTCOME:  An error TechniqueResult is returned — NOT a Python exception.
                  The shell must remain usable; exceptions break the REPL.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("this/does/not/exist", credential_id=1)

        assert isinstance(result, TechniqueResult)
        assert result.status == "error"
        assert result.error is not None
        assert len(result.error) > 0

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_missing_credential_returns_error_result_not_exception(
        self, tmp_path, request, transport_fixture, loader, mock_aws_registry
    ):
        """
        SCENARIO: run_technique called with a credential_id that doesn't exist.
        OUTCOME:  Error result with a message the operator can act on.
                  Never an unhandled exception.
        """
        ws = Workspace.create("missing-cred", tmp_path)
        transport = LocalTransport(ws, loader, mock_aws_registry)

        result = transport.run_technique("discovery/whoami", credential_id=999)

        assert result.status == "error"
        assert result.error is not None
        ws.close()

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_no_active_credential_returns_error_result_not_exception(
        self, tmp_path, request, transport_fixture, loader, mock_aws_registry
    ):
        """
        SCENARIO: Workspace exists but has no active credential set.
        OUTCOME:  Operator-readable error result — not an unhandled AttributeError
                  or NoneType on the provider dispatch path.
        """
        ws = Workspace.create("no-active", tmp_path)
        transport = LocalTransport(ws, loader, mock_aws_registry)

        # No credential added, no active_credential_id set
        result = transport.run_technique("discovery/whoami")

        assert result.status == "error"
        assert "credential" in result.error.lower()
        ws.close()

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_successful_result_includes_provider(self, request, transport_fixture):
        """
        OUTCOME: A successful result names the provider it ran against.

        The timeline and attack path need this to differentiate
        AWS from Azure from GCP results.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("discovery/whoami", credential_id=1)

        assert result.provider in ("aws", "azure", "gcp", "oci"), (
            f"Result provider '{result.provider}' is not a known cloud provider."
        )

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_error_result_never_has_status_success(self, request, transport_fixture):
        """
        OUTCOME: Error results are never mislabelled as success.

        A mislabelled error is worse than a missed success — it produces
        false evidence in the engagement record.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = transport.run_technique("nonexistent/technique", credential_id=1)

        assert result.status != "success"


# ================================================================
# CONTRACT: list_techniques
# ================================================================

class TestListTechniquesContract:
    """
    SCENARIO: Operator or agent needs to know what's available.
    OUTCOME:  A list of technique metadata with at least one entry.
    """

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_list_techniques_returns_a_sequence(self, request, transport_fixture):
        transport = request.getfixturevalue(transport_fixture)
        result = transport.list_techniques()

        assert hasattr(result, "__iter__"), "list_techniques must return an iterable"

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_list_techniques_is_not_empty(self, request, transport_fixture):
        """
        OUTCOME: At least one technique is always available.

        An empty list means the technique loader is broken — the agent
        can't make any decisions, and the engagement is stuck.
        """
        transport = request.getfixturevalue(transport_fixture)
        result = list(transport.list_techniques())

        assert len(result) > 0, "Transport returned zero techniques — loader is broken."

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_list_techniques_each_has_id_and_provider(self, request, transport_fixture):
        """
        OUTCOME: Every technique entry has at minimum an id and provider list.

        The agent's decision loop uses these fields. Missing fields = broken agent.
        """
        transport = request.getfixturevalue(transport_fixture)
        techniques = list(transport.list_techniques())

        for t in techniques:
            assert hasattr(t, "id"), (
                f"Technique entry lacks 'id': {t}"
            )
            assert hasattr(t, "providers"), (
                f"Technique entry lacks 'providers': {t}"
            )

    @pytest.mark.parametrize("transport_fixture", ["local_transport"])
    def test_filter_by_provider_returns_only_matching(self, request, transport_fixture):
        """
        SCENARIO: Agent filters techniques for the active provider.
        OUTCOME:  Only techniques that support 'aws' are returned when provider='aws'.
        """
        transport = request.getfixturevalue(transport_fixture)
        aws_techniques = list(transport.list_techniques(provider="aws"))
        all_techniques = list(transport.list_techniques())

        # aws-filtered must be a subset
        assert len(aws_techniques) <= len(all_techniques)
        # aws-filtered must be non-empty — we have aws techniques
        assert len(aws_techniques) > 0


# ================================================================
# LAYER 4: SECURITY TESTS
# ================================================================

class TestTransportSecurityContract:
    """
    These tests verify that the Transport enforces security invariants.
    A transport that passes these tests does not silently bypass auth,
    does not leak credentials between workspaces, and does not allow
    technique execution without a valid credential.

    ANTI-GAMIFICATION: These tests must fail if auth is removed.
    They are not checking that we call auth() — they are checking
    that without valid auth, the result is an error.
    """

    def test_cross_workspace_credential_isolation(self, tmp_path, loader, mock_aws_registry):
        """
        SCENARIO: Two workspaces exist. Workspace A has a credential.
                  Workspace B has no credentials. An operator on workspace B
                  tries to use credential #1 (which exists in workspace A).

        OUTCOME:  Workspace B returns an error. Credentials from workspace A
                  are not usable in workspace B.

        This is a real security boundary. If it fails, an adversary who
        compromises one engagement context can use credentials from another.
        """
        ws_a = Workspace.create("ws-a", tmp_path / "a")
        ws_b = Workspace.create("ws-b", tmp_path / "b")

        ws_a.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "a-creds"}),
            friendly_name="a-key",
        )

        transport_b = LocalTransport(ws_b, loader, mock_aws_registry)

        # Try to use credential #1 from workspace A in workspace B's transport
        result = transport_b.run_technique("discovery/whoami", credential_id=1)

        assert result.status == "error", (
            "Workspace B accepted a credential from workspace A. "
            "Credential isolation is broken."
        )

        ws_a.close()
        ws_b.close()

    def test_deleted_credential_cannot_be_used(self, tmp_path, loader, mock_aws_registry):
        """
        SCENARIO: A credential is imported and then deleted.
        OUTCOME:  Attempting to run a technique with the deleted credential
                  returns an error. The deleted credential is not silently
                  falling back to another one.
        """
        ws = Workspace.create("deletion-test", tmp_path)
        cred_id = ws.add_credential(
            provider="aws",
            credential_type="access_key",
            secret_data=json.dumps({"profile_name": "to-delete"}),
            friendly_name="disposable",
        )
        ws.delete_credential(cred_id)

        transport = LocalTransport(ws, loader, mock_aws_registry)
        result = transport.run_technique("discovery/whoami", credential_id=cred_id)

        assert result.status == "error"
        ws.close()


# ================================================================
# LAYER 5: CHAOS TESTS
# ================================================================

class TestTransportChaosContract:
    """
    These tests verify Transport behaviour under adverse conditions.
    Real environments are hostile: providers time out, networks drop,
    APIs return unexpected responses.

    ANTI-GAMIFICATION: We inject real exceptions at the provider SDK
    boundary, not at the runner level. This catches failures that only
    appear when the real boto3/Azure SDK raises.
    """

    def test_provider_authentication_failure_returns_error_not_exception(
        self, workspace, loader
    ):
        """
        SCENARIO: The cloud provider's authentication call raises an exception
                  (expired credentials, network error, wrong key).
        OUTCOME:  An error TechniqueResult is returned. The shell does not crash.
                  The engagement continues.
        """
        # Build a registry where authenticate() raises — as would happen
        # with an expired token or a network blip during STS auth.
        registry = ProviderRegistry()
        broken_aws = create_autospec(AWSAuthProvider, instance=True)
        broken_aws.provider_name = "aws"
        broken_aws.authenticate.side_effect = RuntimeError("STS endpoint unreachable")
        registry.register(broken_aws)

        transport = LocalTransport(workspace, loader, registry)
        result = transport.run_technique("discovery/whoami", credential_id=1)

        assert result.status == "error"
        assert result.error is not None
        # The operator should know authentication failed
        assert "auth" in result.error.lower() or "sts" in result.error.lower() or "error" in result.error.lower()

    def test_technique_execution_raises_mid_run_returns_error_not_exception(
        self, workspace, loader, mock_aws_registry
    ):
        """
        SCENARIO: A technique's execute() function raises midway through
                  (e.g., paginator fails on page 3 of 10, or the EC2
                  DescribeInstances call returns a throttle error).
        OUTCOME:  The error is caught, returned as TechniqueResult(status='error').
                  The workspace is not left in a corrupted state.
                  The next technique can still be run.
        """
        # Patch the technique execution layer to raise at the provider call level.
        # We patch boto3 paginator, not TechniqueRunner — correct mock layer.
        import boto3
        mock_session = create_autospec(boto3.Session, instance=True)
        mock_aws_registry.get("aws").authenticate.return_value = mock_session

        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_paginator.side_effect = RuntimeError("Throttled")

        transport = LocalTransport(workspace, loader, mock_aws_registry)

        # First run — technique fails mid-execution
        result = transport.run_technique("discovery/enum_compute", credential_id=1)
        assert isinstance(result, TechniqueResult)
        # Could succeed (if enum_compute handles it) or fail — either is acceptable;
        # what must NOT happen is an unhandled exception escaping the transport.

        # Second run — transport must still be usable after a failure
        result2 = transport.run_technique("discovery/whoami", credential_id=1)
        assert isinstance(result2, TechniqueResult), (
            "Transport became unusable after a failed technique run. "
            "This would strand an operator mid-engagement."
        )

    def test_rapid_sequential_runs_all_return_valid_results(
        self, workspace, loader, mock_aws_registry
    ):
        """
        SCENARIO: Agent runs 10 techniques back-to-back without delay.
        OUTCOME:  Every result is a valid TechniqueResult with a known status.
                  No result is None. No result has an unknown status field.

        This catches race conditions, state mutation bugs, and resource
        leaks that only appear under repeated use.
        """
        transport = LocalTransport(workspace, loader, mock_aws_registry)

        results = [
            transport.run_technique("discovery/whoami", credential_id=1)
            for _ in range(10)
        ]

        for i, result in enumerate(results):
            assert isinstance(result, TechniqueResult), f"Run {i} returned None"
            assert result.status in ("success", "error", "skipped"), (
                f"Run {i} returned unknown status '{result.status}'"
            )
            assert result.technique_id == "discovery/whoami", (
                f"Run {i} returned wrong technique_id '{result.technique_id}'"
            )
