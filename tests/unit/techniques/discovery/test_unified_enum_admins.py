from unittest.mock import MagicMock, patch

from quantum_mechanic.techniques.discovery.unified_enum_admins import execute


def _make_ctx(provider="entra"):
    ctx = MagicMock()
    ctx.provider_name = provider
    return ctx


def test_entra_path_delegates_to_entra_enum_privileged_roles():
    """OUTCOME: unified_enum_admins entra path maps privileged_roles assignments to admins schema.

    ANTI-GAMIFICATION: patching entra_enum_privileged_roles.execute verifies delegation.
    """
    fake_privesc_result = {
        "provider": "entra",
        "status": "success",
        "assignments": [
            {
                "tier": "Tier 0 (Critical)",
                "role_name": "Global Administrator",
                "principal_name": "alice@corp.example",
                "principal_id": "oid-1",
                "principal_type": "user",
                "assignment_type": "Active/Permanent",
            },
        ],
        "tenant_id": "tid-1",
    }
    ctx = _make_ctx("entra")

    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_admins.entra_enum_privileged_roles.execute",
        return_value=fake_privesc_result,
    ) as mock_delegate:
        result = execute(ctx)

    mock_delegate.assert_called_once_with(ctx)
    assert result["admins"][0]["principal"] == "alice@corp.example"
    assert result["admins"][0]["role"] == "Global Administrator"
    assert "Tier 0" in result["admins"][0]["reason"]


def test_entra_path_returns_empty_admins_on_no_assignments():
    """OUTCOME: empty assignments → empty admins list, not an error."""
    ctx = _make_ctx("entra")
    fake_empty = {
        "provider": "entra",
        "status": "success",
        "assignments": [],
        "tenant_id": "tid-1",
    }
    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_admins.entra_enum_privileged_roles.execute",
        return_value=fake_empty,
    ):
        result = execute(ctx)

    assert result["admins"] == []
    assert result["status"] == "success"


def test_entra_path_propagates_error():
    """OUTCOME: if privileged_roles returns an error dict, it is surfaced cleanly."""
    ctx = _make_ctx("entra")
    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_admins.entra_enum_privileged_roles.execute",
        return_value={"error": "No Graph token available."},
    ):
        result = execute(ctx)

    assert result["status"] == "error"
    assert "admins" in result
    assert result["admins"] == []
