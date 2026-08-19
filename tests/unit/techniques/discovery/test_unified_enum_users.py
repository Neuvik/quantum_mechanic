from unittest.mock import MagicMock, patch

from quantum_mechanic.techniques.discovery.unified_enum_users import execute


def _make_ctx(provider="entra"):
    ctx = MagicMock()
    ctx.provider_name = provider
    return ctx


def test_entra_path_delegates_to_entra_enum_users():
    """OUTCOME: unified_enum_users entra path returns what entra_enum_users returns.

    ANTI-GAMIFICATION: We patch entra_enum_users.execute directly to verify
    delegation — if the unified module reimplements the call instead of
    delegating, patching entra_enum_users.execute would have no effect.
    """
    fake_result = {
        "provider": "entra",
        "total": 2,
        "guests": 1,
        "disabled": 0,
        "users": [
            {"username": "a@b.example", "type": "Member", "id": "u1", "info": "—"},
            {"username": "g@c.example", "type": "Guest", "id": "u2", "info": "—"},
        ],
    }
    ctx = _make_ctx("entra")

    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_users.entra_enum_users.execute",
        return_value=fake_result,
    ) as mock_delegate:
        result = execute(ctx)

    mock_delegate.assert_called_once_with(ctx)
    assert result["total"] == 2
    assert result["users"][0]["username"] == "a@b.example"


def test_azure_path_delegates_to_entra_enum_users():
    """OUTCOME: azure path also delegates (Azure users are Entra principals)."""
    fake_result = {"provider": "entra", "total": 1, "users": [{"username": "x@y.example"}]}
    ctx = _make_ctx("azure")

    with patch(
        "quantum_mechanic.techniques.discovery.unified_enum_users.entra_enum_users.execute",
        return_value=fake_result,
    ) as mock_delegate:
        result = execute(ctx)

    mock_delegate.assert_called_once_with(ctx)
    assert result["total"] == 1


def test_aws_path_not_affected():
    """OUTCOME: non-entra paths are unchanged — AWS uses IAM paginator."""
    import boto3
    from unittest.mock import create_autospec
    from datetime import datetime

    ctx = _make_ctx("aws")
    session = create_autospec(boto3.Session, instance=True)
    ctx.session = session
    iam = MagicMock()
    session.client.return_value = iam
    created = MagicMock()
    created.strftime.return_value = "2024-01-01"
    iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": "alice", "UserId": "uid1", "CreateDate": created}]}
    ]

    result = execute(ctx)

    assert result["users"][0]["username"] == "alice"
