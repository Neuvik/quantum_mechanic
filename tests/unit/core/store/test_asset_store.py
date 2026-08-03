# ================================================================
# TESTS: quantum_mechanic.core.store.assets
# ----------------------------------------------------------------
# WHAT:   Isolated tests for AssetStore (compute instances and
#         network assets — upsert + list).
#
# WHY:    ON CONFLICT … DO UPDATE logic is subtle. We need explicit
#         tests verifying that repeating enum_compute updates rows
#         in place rather than stacking duplicates, and that the
#         list provider-filter works correctly.
# ================================================================

import pytest

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.assets import AssetStore


@pytest.fixture
def db(workspace_db):
    return workspace_db


@pytest.fixture
def store(workspace_db, workspace_id):
    return AssetStore(workspace_db, workspace_id)


# ================================================================
# upsert_compute_instance
# ================================================================

class TestAssetStoreComputeInstance:
    def _add(self, store, **kwargs):
        defaults = dict(
            provider="aws",
            instance_id="i-abc123",
            name="web-server",
            state="running",
            instance_type="t3.micro",
            private_ip="10.0.0.1",
        )
        defaults.update(kwargs)
        store.upsert_compute_instance(**defaults)

    def test_upsert_creates_new_row(self, store):
        self._add(store)
        rows = store.list_compute_instances()
        assert len(rows) == 1
        assert rows[0]["instance_id"] == "i-abc123"

    def test_upsert_updates_existing_row(self, store):
        """Second upsert must update in place — no stacking."""
        self._add(store, state="running")
        self._add(store, state="stopped")
        rows = store.list_compute_instances()
        assert len(rows) == 1
        assert rows[0]["state"] == "stopped"

    def test_two_different_instances_coexist(self, store):
        self._add(store, instance_id="i-111", name="server-a")
        self._add(store, instance_id="i-222", name="server-b")
        assert len(store.list_compute_instances()) == 2

    def test_list_filter_by_provider(self, store):
        self._add(store, provider="aws", instance_id="i-aws")
        self._add(store, provider="gcp", instance_id="i-gcp")
        aws_only = store.list_compute_instances(provider="aws")
        assert len(aws_only) == 1
        assert aws_only[0]["provider"] == "aws"

    def test_list_all_providers_when_no_filter(self, store):
        self._add(store, provider="aws", instance_id="i-1")
        self._add(store, provider="azure", instance_id="i-2")
        self._add(store, provider="gcp", instance_id="i-3")
        assert len(store.list_compute_instances()) == 3

    def test_upsert_updates_last_seen_on_repeat(self, store, db):
        """last_seen must tick forward on every upsert."""
        self._add(store, instance_id="i-ts")
        first_seen = db.fetchone(
            "SELECT first_seen, last_seen FROM compute_instances WHERE instance_id = 'i-ts'"
        )
        import time; time.sleep(0.01)
        self._add(store, instance_id="i-ts", state="stopped")
        second = db.fetchone(
            "SELECT first_seen, last_seen FROM compute_instances WHERE instance_id = 'i-ts'"
        )
        # first_seen must be stable; last_seen must advance
        assert second["first_seen"] == first_seen["first_seen"]
        assert second["last_seen"] >= first_seen["last_seen"]


# ================================================================
# upsert_network_asset
# ================================================================

class TestAssetStoreNetworkAsset:
    def _add(self, store, **kwargs):
        defaults = dict(
            provider="aws",
            asset_type="subnet",
            asset_id="subnet-abc",
            name="private-subnet",
            region="us-east-1",
        )
        defaults.update(kwargs)
        store.upsert_network_asset(**defaults)

    def test_upsert_creates_new_row(self, store, db):
        self._add(store)
        row = db.fetchone("SELECT * FROM network_assets WHERE asset_id = 'subnet-abc'")
        assert row is not None
        assert row["asset_type"] == "subnet"

    def test_upsert_updates_existing_row(self, store, db):
        self._add(store, name="old-name")
        self._add(store, name="new-name")
        row = db.fetchone("SELECT * FROM network_assets WHERE asset_id = 'subnet-abc'")
        assert row["name"] == "new-name"

    def test_different_asset_types_coexist(self, store, db):
        self._add(store, asset_type="subnet", asset_id="subnet-1")
        self._add(store, asset_type="security_group", asset_id="sg-1")
        count = db.fetchone("SELECT COUNT(*) AS c FROM network_assets")
        assert count["c"] == 2

    def test_empty_list_on_empty_store(self, store):
        assert store.list_compute_instances() == []
