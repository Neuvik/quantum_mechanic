"""Tests for the next-steps contextual hint framework (Phase C1).

Techniques emit `next_steps: list[dict]` in their result data. The shell
formatter renders these as a "Suggested next steps:" panel below the
normal output.
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


def test_next_steps_rendered_when_present():
    """OUTCOME: `next_steps` list produces a 'Suggested next steps' panel."""
    result = TechniqueResult(
        technique_id="discovery/entra_enum_identity",
        provider="entra",
        status="success",
        data={
            "principal_id": "abc",
            "next_steps": [
                {"command": "acquire entra arm", "reason": "FOCI RT detected"},
            ],
        },
    )
    out = _capture(result)
    assert "Suggested next steps" in out
    assert "acquire entra arm" in out
    assert "FOCI RT detected" in out


def test_next_steps_absent_when_list_empty():
    """OUTCOME: An empty next_steps list does NOT print a suggestions panel."""
    result = TechniqueResult(
        technique_id="discovery/entra_enum_identity",
        provider="entra",
        status="success",
        data={"principal_id": "abc", "next_steps": []},
    )
    out = _capture(result)
    assert "Suggested next steps" not in out


def test_next_steps_suppressed_on_denied_status():
    """OUTCOME: A denied run does not offer next-steps — nothing to suggest yet.

    ANTI-GAMIFICATION: If we regress this, operators get suggested next-steps
    on a failed enum which is noise. Hints only surface when the enum succeeded.
    """
    result = TechniqueResult(
        technique_id="discovery/entra_enum_users",
        provider="entra",
        status="denied",
        data={
            "error": "HTTP 403",
            "required_scope": "User.Read.All",
            "next_steps": [{"command": "run collection/entra_export_bloodhound", "reason": "..."}],
        },
        error="HTTP 403",
    )
    out = _capture(result)
    assert "Suggested next steps" not in out


def test_entra_users_emits_bloodhound_hint_after_success():
    """OUTCOME: entra_enum_users returns a bloodhound-export hint when users were found."""
    from unittest.mock import MagicMock, patch
    from quantum_mechanic.techniques.discovery import entra_enum_users

    ctx = MagicMock()
    fake_token = MagicMock()
    fake_token.value = "fake"
    fake_token.token_type = "access_token"
    ctx.session.best_token.return_value = fake_token
    ctx.session.tenant_id = "t"

    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_users.graph_list",
        return_value=[{"id": "u1", "userPrincipalName": "a@x.example", "userType": "Member"}],
    ):
        result = entra_enum_users.execute(ctx)

    steps = result.get("next_steps", [])
    assert len(steps) == 1
    assert "entra_export_bloodhound" in steps[0]["command"]


def test_entra_groups_emits_bloodhound_hint_after_success():
    """OUTCOME: entra_enum_groups also returns a bloodhound-export hint."""
    from unittest.mock import MagicMock, patch
    from quantum_mechanic.techniques.discovery import entra_enum_groups

    ctx = MagicMock()
    fake_token = MagicMock()
    fake_token.value = "fake"
    fake_token.token_type = "access_token"
    ctx.session.best_token.return_value = fake_token
    ctx.session.tenant_id = "t"

    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_groups.graph_list",
        return_value=[{"id": "g1", "displayName": "Group One"}],
    ):
        result = entra_enum_groups.execute(ctx)

    steps = result.get("next_steps", [])
    assert any("entra_export_bloodhound" in s["command"] for s in steps)
