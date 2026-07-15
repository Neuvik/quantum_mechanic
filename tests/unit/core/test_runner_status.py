"""Tests for the runner's status derivation and glyph mapping.

Guards Phase A4: The runner must inspect the technique's returned dict for
a `status` field and propagate it to TechniqueResult.status so the shell
formatter can render the right glyph (green ✓ / red ✗ / yellow ⚠).

If any of these regress, techniques that fail with 403 will show a
misleading green ✓ — the exact bug this phase eliminates.
"""
from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueResult, TechniqueRunner
from quantum_mechanic.core.technique import technique
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.aws.auth import AWSAuthProvider
from quantum_mechanic.providers.base import ProviderRegistry, WhoAmIResult


@pytest.fixture
def workspace_with_aws(tmp_path):
    ws = Workspace.create("status-test", tmp_path)
    ws.add_credential(
        provider="aws",
        credential_type="access_key",
        secret_data=json.dumps({"profile_name": "test"}),
        friendly_name="test-key",
    )
    ws._active_credential_id = 1
    yield ws
    ws.close()


@pytest.fixture
def mock_registry_aws():
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


def _make_runner_with_technique(workspace, mock_registry, tech_id, returned_dict):
    """Register a one-shot technique that returns `returned_dict` and build a runner.

    Instead of putting the decorator on a module the loader walks, we directly
    inject a RegisteredTechnique into a fresh loader's internal dict.
    """
    from quantum_mechanic.core.loader import RegisteredTechnique
    from quantum_mechanic.core.technique import TechniqueMetadata

    def _fake_execute(ctx):
        return returned_dict

    meta = TechniqueMetadata(
        id=tech_id,
        tactic="discovery",
        mitre_id="T1000",
        providers=["aws"],
        severity="info",
        safe=True,
        description=f"Test technique {tech_id}",
    )
    _fake_execute.__technique__ = meta  # match what the real decorator sets

    loader = TechniqueLoader()
    loader._techniques[tech_id] = RegisteredTechnique(
        metadata=meta,
        function=_fake_execute,
        module_path="tests.unit.core.test_runner_status",
    )
    return TechniqueRunner(workspace, loader, mock_registry)


def test_runner_maps_technique_denied_to_outer_denied(workspace_with_aws, mock_registry_aws):
    """OUTCOME: When a technique returns {"status": "denied"}, the runner's
    TechniqueResult.status is 'denied' (not silently 'success').

    ANTI-GAMIFICATION: This is the primary regression guard for the whole
    Phase A honest-errors work — if the runner ever hardcodes 'success'
    again, this test fails.
    """
    tech_id = "discovery/_test_denied_technique"
    runner = _make_runner_with_technique(
        workspace_with_aws,
        mock_registry_aws,
        tech_id,
        {"status": "denied", "error": "HTTP 403", "required_scope": "Foo.Read.All"},
    )
    result = runner.run(tech_id)
    assert result.status == "denied"
    assert "403" in (result.error or "")


def test_runner_maps_technique_partial_to_outer_partial(workspace_with_aws, mock_registry_aws):
    """OUTCOME: {"status": "partial"} propagates to TechniqueResult.status='partial'."""
    tech_id = "discovery/_test_partial_technique"
    runner = _make_runner_with_technique(
        workspace_with_aws,
        mock_registry_aws,
        tech_id,
        {"status": "partial", "items": [{"a": 1}]},
    )
    result = runner.run(tech_id)
    assert result.status == "partial"


def test_runner_treats_missing_status_as_success(workspace_with_aws, mock_registry_aws):
    """OUTCOME: Techniques predating the contract (no 'status' key) are treated
    as success — required for backward compat per spec.md §3.6."""
    tech_id = "discovery/_test_no_status_technique"
    runner = _make_runner_with_technique(
        workspace_with_aws,
        mock_registry_aws,
        tech_id,
        {"items": [1, 2, 3]},  # no status field
    )
    result = runner.run(tech_id)
    assert result.status == "success"


def test_shell_formatter_renders_red_x_for_denied_status():
    """OUTCOME: format_technique_result on a denied TechniqueResult prints a red ✗
    and the required scope hint. Confirms A4's glyph mapping reaches the operator.
    """
    from quantum_mechanic.shell import formatters as f

    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = f.console
    f.console = fake_console
    try:
        result = TechniqueResult(
            technique_id="discovery/entra_enum_users",
            provider="entra",
            status="denied",
            data={"error": "HTTP 403 on /users", "required_scope": "User.Read.All"},
            error="HTTP 403 on /users",
        )
        f.format_technique_result(result)
    finally:
        f.console = orig

    out = buf.getvalue()
    assert "✗" in out, f"expected red ✗ glyph in output, got: {out!r}"
    assert "User.Read.All" in out, f"expected required scope in output, got: {out!r}"


def test_shell_formatter_renders_yellow_warning_for_partial_status():
    """OUTCOME: format_technique_result on a partial TechniqueResult prints yellow ⚠."""
    from quantum_mechanic.shell import formatters as f

    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = f.console
    f.console = fake_console
    try:
        result = TechniqueResult(
            technique_id="discovery/entra_enum_users",
            provider="entra",
            status="partial",
            data={"users": [{"id": "a"}]},
        )
        f.format_technique_result(result)
    finally:
        f.console = orig

    out = buf.getvalue()
    assert "⚠" in out, f"expected yellow ⚠ glyph for partial, got: {out!r}"
