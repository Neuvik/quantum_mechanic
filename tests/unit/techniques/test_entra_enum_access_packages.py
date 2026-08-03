"""Unit tests for discovery/entra_enum_access_packages."""
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_access_packages import execute


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def _make_access_token() -> EntraToken:
    return EntraToken(
        token_type="access_token",
        value="eyJ.fake.access",
        resource=GRAPH,
        tenant_id="tenant-123",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
    )


def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="tenant-123", user_upn="alice@contoso.com")
    if token:
        store.add_token(token)
    return store


def _make_ctx(store):
    ctx = MagicMock()
    ctx.session = store
    ctx.provider_name = "entra"
    return ctx


def test_no_token_returns_error():
    """OUTCOME: missing token returns clean error."""
    ctx = _make_ctx(_make_store())
    result = execute(ctx)
    assert "error" in result


def test_happy_path_returns_packages_and_assignments():
    """OUTCOME: returns parsed access packages and assignments."""
    packages = [
        {
            "id": "pkg-1",
            "displayName": "Engineering Privileged Access",
            "description": "Privileged",
        },
    ]
    assignments = [
        {
            "id": "asn-1",
            "accessPackage": {"id": "pkg-1", "displayName": "Engineering Privileged Access"},
            "target": {
                "id": "tgt-1",
                "displayName": "alice@contoso.com",
                "principalType": "user",
            },
            "state": "delivered",
        },
    ]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_access_packages.graph_list",
        side_effect=[packages, assignments],
    ):
        result = execute(ctx)

    assert "packages" in result
    assert "assignments" in result
    assert len(result["packages"]) == 1
    assert len(result["assignments"]) == 1
    assert result["packages"][0]["display_name"] == "Engineering Privileged Access"
    assert result["assignments"][0]["package_name"] == "Engineering Privileged Access"
    assert result["assignments"][0]["target_name"] == "alice@contoso.com"


def test_403_on_packages_returns_error():
    """OUTCOME: 403 from /accessPackages returns clean error."""
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_access_packages.graph_list",
        side_effect=Exception("403 Forbidden"),
    ):
        result = execute(ctx)
    assert "error" in result


def test_packages_no_assignments_still_returns_packages():
    """OUTCOME: even if /assignments is empty, the packages list is returned."""
    packages = [{"id": "pkg-1", "displayName": "Test Package", "description": "Desc"}]
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_access_packages.graph_list",
        side_effect=[packages, []],
    ):
        result = execute(ctx)

    assert result.get("status") == "success"
    assert len(result["packages"]) == 1
    assert result["assignments"] == []


def test_empty_state_is_status_success():
    """OUTCOME: no packages, no assignments → status success, both empty."""
    ctx = _make_ctx(_make_store(_make_access_token()))
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_access_packages.graph_list",
        side_effect=[[], []],
    ):
        result = execute(ctx)

    assert result["status"] == "success"
    assert result["packages"] == []
    assert result["assignments"] == []
