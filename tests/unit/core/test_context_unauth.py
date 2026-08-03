"""Regression guard for ExecutionContext with provider=None.

Reported from a live engagement (barrier-reef workspace):

    qm[barrier-reef]> run recon/discovery_domains
      Enter domain (e.g. contoso.com):
      > target-org.example
      ✗ Transport internal error: 'NoneType' object has no attribute 'provider_name'

Root cause: unauth techniques (providers=[]) run with no credential and
therefore no provider object. Runner passes provider=None; the ctx
constructor blindly did `provider.provider_name` — instant crash on
every recon/* technique.

These tests lock in that ExecutionContext can be built with provider=None
and reports "none" as the provider_name (matching the runner's telemetry
convention).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from quantum_mechanic.core.context import ExecutionContext


def test_context_constructs_when_provider_is_none():
    """OUTCOME: The exact call the runner makes for unauth techniques
    does not raise. Before the fix this raised AttributeError.
    """
    ctx = ExecutionContext(
        workspace=MagicMock(),
        credential_id=None,
        provider=None,
        session=None,
        technique_id="recon/discovery_domains",
        safe_mode=False,
        params={"domain": "example.com"},
    )
    assert ctx.provider_name == "none"


def test_context_provider_name_when_provider_present():
    """OUTCOME: The authenticated path is unchanged — provider_name still
    comes from provider.provider_name."""
    fake_provider = MagicMock()
    fake_provider.provider_name = "aws"
    ctx = ExecutionContext(
        workspace=MagicMock(),
        credential_id=1,
        provider=fake_provider,
        session=MagicMock(),
        technique_id="discovery/whoami",
        safe_mode=False,
        params={},
    )
    assert ctx.provider_name == "aws"


def test_unauth_technique_execute_receives_none_provider_name():
    """OUTCOME: When runner dispatches an unauth technique end-to-end, the
    ctx that reaches the technique reports provider_name='none' without
    crashing anywhere along the way.
    """
    from quantum_mechanic.core.runner import TechniqueRunner

    # Register a fake unauth technique that just returns ctx.provider_name.
    from quantum_mechanic.core.loader import RegisteredTechnique, TechniqueLoader
    from quantum_mechanic.core.technique import TechniqueMetadata

    def _fake_execute(ctx):
        return {"status": "success", "provider_seen": ctx.provider_name}

    meta = TechniqueMetadata(
        id="recon/_test_unauth",
        tactic="recon",
        mitre_id="T0000",
        providers=[],   # unauth — no credential required
        severity="info",
        safe=True,
        description="Test unauth technique",
    )
    _fake_execute.__technique__ = meta

    import tempfile
    from pathlib import Path
    from quantum_mechanic.core.workspace import Workspace
    from quantum_mechanic.providers.base import ProviderRegistry

    with tempfile.TemporaryDirectory() as td:
        ws = Workspace.create("unauth-ctx-test", workspace_dir=Path(td))
        loader = TechniqueLoader()
        loader._techniques["recon/_test_unauth"] = RegisteredTechnique(
            metadata=meta,
            function=_fake_execute,
            module_path="tests.unit.core.test_context_unauth",
        )
        runner = TechniqueRunner(ws, loader, ProviderRegistry())

        result = runner.run("recon/_test_unauth")
        assert result.status == "success", (
            f"Unauth technique crashed with {result.status!r}: {result.error!r}. "
            "This is the exact bug reported from the barrier-reef engagement."
        )
        assert result.data["provider_seen"] == "none"
        ws.close()
