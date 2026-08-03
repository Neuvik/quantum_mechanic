"""Tests for the denied-time FOCI-expansion remediation hint (Phase C2).

Full semi-automatic prompt-and-retry is deferred; this covers the
lightweight version: when a technique returns denied + required_scope,
the formatter suggests the acquire-arm command the operator can run
manually to mint a token with the needed scope.
"""
from __future__ import annotations

from io import StringIO

from rich.console import Console

from quantum_mechanic.core.runner import TechniqueResult
from quantum_mechanic.shell import formatters as f


def _capture(result: TechniqueResult) -> str:
    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = f.console
    f.console = fake_console
    try:
        f.format_technique_result(result)
    finally:
        f.console = orig
    return buf.getvalue()


def test_denied_with_required_scope_shows_diagnostic_hint():
    """OUTCOME: A denied result with required_scope prints a diagnostic hint
    that names the scope and explains why FOCI can't just mint it.
    """
    result = TechniqueResult(
        technique_id="discovery/entra_enum_access_packages",
        provider="entra",
        status="denied",
        data={
            "error": "HTTP 403 on /identityGovernance/entitlementManagement",
            "required_scope": "EntitlementManagement.Read.All",
        },
        error="HTTP 403",
    )
    out = _capture(result)
    assert "EntitlementManagement.Read.All" in out
    assert "Graph permission" in out
    # The hint must explain the real remediation path, not a fake command.
    assert "app registration" in out.lower() or "admin consent" in out.lower()


def test_denied_without_required_scope_no_hint():
    """OUTCOME: If the technique didn't populate required_scope, no fake hint
    is invented — we only surface guidance when we know what scope is missing.
    """
    result = TechniqueResult(
        technique_id="discovery/entra_enum_users",
        provider="entra",
        status="denied",
        data={"error": "HTTP 403 on /users"},
        error="HTTP 403",
    )
    out = _capture(result)
    assert "Graph permission" not in out
    assert "app registration" not in out


def test_error_status_does_not_show_scope_diagnostic():
    """OUTCOME: status='error' is not a scope problem — no scope diagnostic."""
    result = TechniqueResult(
        technique_id="discovery/entra_enum_users",
        provider="entra",
        status="error",
        data={"error": "Backend 503", "required_scope": "User.Read.All"},
        error="503",
    )
    out = _capture(result)
    # The base Required-scope line still appears but the scope-not-obtainable
    # diagnostic should NOT — 503 is a service problem, not a permission problem.
    assert "app registration" not in out
    assert "cannot mint" not in out.lower()


def test_hint_never_suggests_acquire_arm_with_scope_flag():
    """ANTI-GAMIFICATION regression guard.

    In a real engagement, the C2 hint told an operator to run
    `acquire entra arm --scope EntitlementManagement.Read.All`. The `--scope`
    flag is silently discarded by `_acquire_arm` (see commands_entra.py:574),
    ARM tokens don't carry Graph scopes, and the operator wasted several
    minutes running the same 403 in a loop.

    If any future change reintroduces that hint text, this test fails.
    """
    result = TechniqueResult(
        technique_id="discovery/entra_enum_access_packages",
        provider="entra",
        status="denied",
        data={
            "error": "HTTP 403",
            "required_scope": "EntitlementManagement.Read.All",
        },
        error="HTTP 403",
    )
    out = _capture(result)
    assert "acquire entra arm --scope" not in out, (
        "The C2 hint must NOT suggest `acquire entra arm --scope <X>` — "
        "that command silently ignores --scope and ARM tokens can't carry "
        "Graph permissions. This regressed in a real engagement session."
    )
    # Same for the refresh variant: `acquire entra refresh` uses .default,
    # it does not accept an arbitrary Graph permission as --scope either.
    assert "acquire entra refresh --scope" not in out
