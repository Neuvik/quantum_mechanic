# ================================================================
# TESTS: quantum_mechanic.core.database
# ----------------------------------------------------------------
# WHAT:   Tests the SQLite database wrapper — workspace creation,
#         loading, listing, migrations, and query helpers.
#
# WHY:    The database is the foundation. If migrations fail or
#         queries return wrong types, everything downstream breaks.
# ================================================================


import pytest

from quantum_mechanic.core.database import Database


@pytest.fixture
def workspace_dir(tmp_path):
    """Provide a temporary directory for workspace databases."""
    return tmp_path


class TestDatabaseCreate:
    """Test workspace database creation."""

    def test_create_new_workspace(self, workspace_dir):
        """Creating a workspace produces a .db file and applies migrations."""
        db = Database.create("test-ws", workspace_dir)
        assert (workspace_dir / "test-ws.db").exists()
        db.close()

    def test_create_applies_migrations(self, workspace_dir):
        """Migrations table exists and initial migration is tracked."""
        db = Database.create("test-ws", workspace_dir)
        rows = db.fetchall("SELECT filename FROM _migrations")
        filenames = [r["filename"] for r in rows]
        assert "001_initial_schema.sql" in filenames
        db.close()

    def test_create_initializes_workspace_row(self, workspace_dir):
        """The workspace table has exactly one row after creation."""
        db = Database.create("my-engagement", workspace_dir)
        row = db.fetchone("SELECT name FROM workspace")
        assert row is not None
        assert row["name"] == "my-engagement"
        db.close()

    def test_create_duplicate_raises(self, workspace_dir):
        """Creating a workspace that already exists raises FileExistsError."""
        db = Database.create("dupe", workspace_dir)
        db.close()
        with pytest.raises(FileExistsError):
            Database.create("dupe", workspace_dir)


class TestDatabaseLoad:
    """Test loading existing workspaces."""

    def test_load_existing(self, workspace_dir):
        """Loading an existing workspace returns a working database."""
        db1 = Database.create("existing", workspace_dir)
        db1.close()

        db2 = Database.load("existing", workspace_dir)
        row = db2.fetchone("SELECT name FROM workspace")
        assert row["name"] == "existing"
        db2.close()

    def test_load_missing_raises(self, workspace_dir):
        """Loading a non-existent workspace raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            Database.load("nonexistent", workspace_dir)


class TestDatabaseList:
    """Test workspace listing."""

    def test_list_empty(self, workspace_dir):
        """Listing with no workspaces returns empty list."""
        workspaces = Database.list_workspaces(workspace_dir)
        assert workspaces == []

    def test_list_multiple(self, workspace_dir):
        """Listing returns all workspaces sorted by name."""
        for name in ["alpha", "beta", "gamma"]:
            db = Database.create(name, workspace_dir)
            db.close()

        workspaces = Database.list_workspaces(workspace_dir)
        names = [w["name"] for w in workspaces]
        assert names == ["alpha", "beta", "gamma"]

    def test_list_missing_dir(self, workspace_dir):
        """Listing when the directory doesn't exist returns an empty list."""
        missing_dir = workspace_dir / "does_not_exist"
        workspaces = Database.list_workspaces(missing_dir)
        assert workspaces == []


class TestDatabaseQueries:
    """Test query helper methods."""

    def test_execute_and_fetchone(self, workspace_dir):
        """fetchone returns a single row with dict-like access."""
        db = Database.create("query-test", workspace_dir)
        row = db.fetchone("SELECT count(*) AS cnt FROM workspace")
        assert row["cnt"] == 1
        db.close()

    def test_fetchall(self, workspace_dir):
        """fetchall returns all matching rows."""
        db = Database.create("fetchall-test", workspace_dir)
        rows = db.fetchall("SELECT * FROM _migrations")
        assert len(rows) >= 1
        db.close()

    def test_execute_many(self, workspace_dir):
        """execute_many processes a batch of parameterized rows."""
        db = Database.create("executemany-test", workspace_dir)
        db.execute("CREATE TABLE test_batch (id INTEGER PRIMARY KEY, val TEXT)")
        db.execute_many("INSERT INTO test_batch (val) VALUES (?)", [("a",), ("b",), ("c",)])
        db.commit()
        
        rows = db.fetchall("SELECT val FROM test_batch ORDER BY val")
        assert [r["val"] for r in rows] == ["a", "b", "c"]
        db.close()

    def test_schema_tables_exist(self, workspace_dir):
        """All MVP tables exist after initial migration."""
        db = Database.create("schema-test", workspace_dir)
        tables = db.fetchall("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        table_names = {r["name"] for r in tables}
        expected = {
            "workspace",
            "accounts",
            "credentials",
            "principals",
            "api_log",
            "_migrations",
        }
        assert expected.issubset(table_names)
        db.close()
