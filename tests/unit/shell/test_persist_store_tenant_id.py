# ================================================================
# TESTS: commands_entra._persist_store — tenant ID correction ordering
# ----------------------------------------------------------------
# _entra_friendly_name() corrects store.tenant_id from the "common"
# placeholder to the real tenant GUID decoded from token claims, as a
# side effect of computing the friendly display name. _persist_store
# must run that correction BEFORE serializing secret_data, or the
# persisted credential keeps the placeholder forever — every later
# `run discovery/entra_whoami` on that credential shows "common"
# instead of the real tenant ID.
# ================================================================
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraToken, EntraTokenStore
from quantum_mechanic.shell.commands_entra import _persist_store


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def test_persist_store_corrects_common_placeholder_before_serializing():
    """OUTCOME: a store acquired with tenant_id="common" (no specific tenant
    pinned at acquisition time) persists the REAL tenant GUID decoded from
    the access token's `tid` claim, not the "common" placeholder."""
    store = EntraTokenStore(tenant_id="common", user_upn="alice@contoso.com")
    store.add_token(EntraToken(
        token_type="access_token",
        value="eyJ.fake.access",
        resource=GRAPH,
        tenant_id="common",
        client_id=FOCI_DEFAULT_CLIENT,
        expires_at=_future(),
        raw_claims={"tid": "real-tenant-guid", "oid": "user-oid-1"},
    ))

    state = MagicMock()
    state.transport = MagicMock()
    state.transport.list_credentials.return_value = []
    state.transport.add_credential.return_value = 1

    _persist_store(state, store)

    persisted = json.loads(state.transport.add_credential.call_args.kwargs["secret_data"])
    assert persisted["token_store"]["tenant_id"] == "real-tenant-guid"
    # The in-memory store is corrected too, matching what later `run` calls
    # against the same in-process object would see.
    assert store.tenant_id == "real-tenant-guid"
