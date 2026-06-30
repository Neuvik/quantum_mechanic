# ================================================================
# TESTS: quantum_mechanic.core.runner
# ----------------------------------------------------------------
# WHAT:   Tests the technique execution engine with mocked
#         providers. Covers credential resolution, provider
#         validation, error handling, and result formatting.
#
# WHY:    The runner is the bridge between shell/agent and
#         technique code. If it doesn't resolve credentials
#         correctly or handle errors gracefully, the tool
#         becomes unreliable.
# ================================================================

import json
from unittest.mock import MagicMock

import pytest

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueResult, TechniqueRunner
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry, WhoAmIResult


@pytest.fixture
def workspace(tmp_path):
    """Create a workspace with a mocked AWS credential."""
    ws = Workspace.create("runner-test", tmp_path)
    ws.add_credential(
        provider="aws",
        credential_type="access_key",
        secret_data=json.dumps({"profile_name": "test"}),
        friendly_name="test-key",
    )
    # Private bypass: tests in this module mock the provider registry, so the
    # real whoami verification can't run. Identity verification is covered by
    # tests/unit/core/test_workspace_active_cred.py.
    ws._active_credential_id = 1
    yield ws
    ws.close()


@pytest.fixture
def mock_registry():
    """Provider registry with a mocked AWS provider."""
    registry = ProviderRegistry()
    mock_aws = MagicMock(spec=AWSAuthProvider)
    mock_aws.provider_name = "aws"
    mock_aws.authenticate.return_value = MagicMock()
    mock_aws.whoami.return_value = WhoAmIResult(
        provider="aws",
        principal_id="arn:aws:iam::123456:user/test",
        principal_type="user",
        friendly_name="test",
        account_id="123456789012",
    )
    registry.register(mock_aws)
    return registry


@pytest.fixture
def loader():
    """Loader with real techniques loaded."""
    ldr = TechniqueLoader()
    ldr.load_all()
    return ldr


class TestTechniqueRunner:
    """Test technique execution."""

    def test_run_whoami_success(self, workspace, mock_registry, loader):
        """Running whoami with mocked provider returns success."""
        runner = TechniqueRunner(workspace, loader, mock_registry)
        result = runner.run("discovery/whoami")

        assert result.status == "success"
        assert result.provider == "aws"
        assert result.technique_id == "discovery/whoami"
        assert result.api_calls >= 1

    def test_run_unknown_technique(self, workspace, mock_registry, loader):
        """Running a nonexistent technique returns an error result."""
        runner = TechniqueRunner(workspace, loader, mock_registry)
        result = runner.run("nonexistent/technique")

        assert result.status == "error"
        assert "not found" in result.error

    def test_run_no_active_credential(self, tmp_path, mock_registry, loader):
        """Running without an active credential returns an error."""
        ws = Workspace.create("no-cred-test", tmp_path)
        runner = TechniqueRunner(ws, loader, mock_registry)
        result = runner.run("discovery/whoami")

        assert result.status == "error"
        assert "No active credential" in result.error
        ws.close()

    def test_run_unsupported_provider(self, tmp_path, loader):
        """Running a technique against an unsupported provider errors."""
        ws = Workspace.create("unsupported-test", tmp_path)
        ws.add_credential(
            provider="oci",
            credential_type="api_key",
            secret_data="{}",
        )
        # Private bypass: this test exercises the runner's no-provider path,
        # not credential identity verification.
        ws._active_credential_id = 1

        registry = ProviderRegistry()
        # No OCI provider registered
        runner = TechniqueRunner(ws, loader, registry)
        result = runner.run("discovery/whoami")

        assert result.status == "error"
        # Should mention either unsupported provider or provider not available
        assert "oci" in result.error.lower() or "not" in result.error.lower()
        ws.close()


class TestTechniqueResult:
    """Test result serialization."""

    def test_to_dict_success(self):
        """Success result serializes to dict cleanly."""
        result = TechniqueResult(
            technique_id="discovery/whoami",
            provider="aws",
            status="success",
            data={"identity": "test"},
            api_calls=1,
            duration_ms=150,
        )
        d = result.to_dict()
        assert d["status"] == "success"
        assert d["technique"] == "discovery/whoami"
        assert d["data"]["identity"] == "test"

    def test_to_dict_error(self):
        """Error result includes error message."""
        result = TechniqueResult(
            technique_id="test/foo",
            provider="aws",
            status="error",
            error="something went wrong",
        )
        d = result.to_dict()
        assert d["status"] == "error"
        assert d["error"] == "something went wrong"

    def test_to_dict_whoami_result(self):
        """WhoAmIResult data serializes via dataclass asdict."""
        result = TechniqueResult(
            technique_id="discovery/whoami",
            provider="aws",
            status="success",
            data=WhoAmIResult(
                provider="aws",
                principal_id="arn:test",
                principal_type="user",
                friendly_name="test",
                account_id="123",
            ),
            api_calls=1,
            duration_ms=100,
        )
        d = result.to_dict()
        assert d["data"]["provider"] == "aws"
        assert d["data"]["friendly_name"] == "test"


class TestFriendlyError:
    """Test exception translation."""

    def test_aws_client_error(self):
        """AWS ClientErrors are translated based on their Code."""
        from quantum_mechanic.core.runner import _friendly_error
        
        class DummyClientError(Exception):
            def __init__(self, code):
                self.response = {"Error": {"Code": code}}
                
        # Known code
        exc1 = DummyClientError("AccessDenied")
        exc1.__class__.__name__ = "ClientError"
        res1 = _friendly_error(exc1, "aws")
        assert "Access denied" in res1
        
        # Unknown code
        exc2 = DummyClientError("WeirdError")
        exc2.__class__.__name__ = "ClientError"
        res2 = _friendly_error(exc2, "aws")
        assert "AWS API error" in res2

    def test_generic_fallback(self):
        """Unknown exceptions fall back cleanly."""
        from quantum_mechanic.core.runner import _friendly_error
        
        exc = ValueError("Something bad")
        res = _friendly_error(exc, "oci")
        assert "Error: Something bad" in res
