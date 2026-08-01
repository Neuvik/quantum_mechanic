from __future__ import annotations

from io import StringIO

from rich.console import Console

from quantum_mechanic.core.runner import TechniqueResult
from quantum_mechanic.shell import formatters as shell_formatters
from quantum_mechanic.techniques.discovery.entra_enum_privileged_roles import (
    format_privileged_roles,
)


def _capture(result: TechniqueResult) -> str:
    buf = StringIO()
    fake_console = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = shell_formatters.console
    shell_formatters.console = fake_console
    try:
        format_privileged_roles(result)
    finally:
        shell_formatters.console = orig
    return buf.getvalue()


def test_partial_privileged_roles_formatter_surfaces_missing_scope_guidance():
    """OUTCOME: partial privileged-role results tell the operator the PIM
    view is incomplete and show the exact follow-up command."""
    result = TechniqueResult(
        technique_id="discovery/entra_enum_privileged_roles",
        provider="entra",
        status="partial",
        data={
            "status": "partial",
            "assignments": [
                {
                    "tier": "ControlPlane",
                    "role_name": "Global Administrator",
                    "principal_name": "alice@contoso.example",
                    "principal_type": "user",
                    "assignment_type": "Active/Permanent",
                    "expires_at": None,
                }
            ],
            "visibility": {
                "active_assignments": True,
                "pim_eligibility": False,
                "pim_activated": False,
            },
            "missing_scopes": [
                "RoleEligibilitySchedule.Read.Directory",
                "RoleAssignmentSchedule.Read.Directory",
            ],
        },
        formatter_func=format_privileged_roles,
    )

    out = _capture(result)
    assert "PIM visibility incomplete" in out
    assert "RoleEligibilitySchedule.Read.Directory" in out
    assert "RoleAssignmentSchedule.Read.Directory" in out
    assert "acquire entra interactive --bundle pim-read" in out
