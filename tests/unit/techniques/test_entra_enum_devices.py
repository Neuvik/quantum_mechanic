# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.entra_enum_devices
# ================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.techniques.discovery.entra_enum_devices import execute


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _make_token(token_type: str = "access_token") -> EntraToken:
    return EntraToken(
        token_type=token_type,
        value="eyJ.fake",
        resource=GRAPH,
        tenant_id="t",
        expires_at=_future(),
        foci=True,
        client_id=FOCI_DEFAULT_CLIENT,
    )


def _make_store(token: EntraToken | None = None) -> EntraTokenStore:
    store = EntraTokenStore(tenant_id="t")
    if token:
        store.add_token(token)
    return store


def _build_ctx(store: EntraTokenStore) -> MagicMock:
    ctx = MagicMock(spec=ExecutionContext)
    ctx.session = store
    ctx.log_api_call = MagicMock()
    return ctx


_SAMPLE_DEVICES = [
    {
        "id": "d1", "displayName": "LAPTOP-WIN11",
        "operatingSystem": "Windows", "operatingSystemVersion": "10.0.22621",
        "trustType": "AzureAD", "isCompliant": True, "isManaged": True,
    },
    {
        "id": "d2", "displayName": "MACBOOK-DEV",
        "operatingSystem": "MacMDM", "operatingSystemVersion": "14.0",
        "trustType": "Workplace", "isCompliant": False, "isManaged": False,
    },
    {
        "id": "d3", "displayName": "HYBRID-WIN10",
        "operatingSystem": "Windows", "operatingSystemVersion": "10.0.19045",
        "trustType": "ServerAD", "isCompliant": True, "isManaged": True,
    },
    {
        "id": "d4", "displayName": "IPHONE-CORP",
        "operatingSystem": "iOS", "operatingSystemVersion": "17.0",
        "trustType": "Workplace", "isCompliant": None, "isManaged": False,
    },
]


def _run(devices: list = _SAMPLE_DEVICES) -> dict:
    store = _make_store(_make_token())
    ctx = _build_ctx(store)
    http_mock = MagicMock()
    http_mock.__enter__ = lambda s: http_mock
    http_mock.__exit__ = MagicMock(return_value=False)
    with patch(
        "quantum_mechanic.techniques.discovery.entra_enum_devices.graph_list",
        return_value=devices,
    ), patch(
        "quantum_mechanic.techniques.discovery.entra_enum_devices.httpx.Client",
        return_value=http_mock,
    ):
        return execute(ctx)


class TestNoToken:
    def test_returns_error(self):
        result = execute(_build_ctx(_make_store()))
        assert "error" in result


class TestEnumDevices:
    def test_total_count(self):
        assert _run()["total"] == 4

    def test_non_compliant_count(self):
        # isCompliant=False counts; None (unknown) does not
        assert _run()["non_compliant"] == 1

    def test_by_trust_type(self):
        by_trust = _run()["by_trust_type"]
        assert by_trust.get("AzureAD") == 1
        assert by_trust.get("ServerAD") == 1
        assert by_trust.get("Workplace") == 2

    def test_devices_list(self):
        assert len(_run()["devices"]) == 4

    def test_tenant_id(self):
        assert _run()["tenant_id"] == "t"

    def test_provider(self):
        assert _run()["provider"] == "entra"

    def test_empty_tenant(self):
        result = _run(devices=[])
        assert result["total"] == 0
        assert result["non_compliant"] == 0
        assert result["by_trust_type"] == {}

    def test_all_compliant(self):
        devices = [
            {"id": "d1", "trustType": "AzureAD", "isCompliant": True, "isManaged": True},
            {"id": "d2", "trustType": "AzureAD", "isCompliant": True, "isManaged": True},
        ]
        result = _run(devices=devices)
        assert result["non_compliant"] == 0

    def test_foci_expansion_error(self):
        store = _make_store(_make_token("refresh_token"))
        ctx = _build_ctx(store)
        with patch("quantum_mechanic.techniques.discovery.entra_enum_devices.foci_expand", return_value=None):
            result = execute(ctx)
        assert "error" in result
