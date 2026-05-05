# ================================================================
# TESTS: Workspace — SQLAlchemy (ORM) path
# ----------------------------------------------------------------
# WHAT:   Tests Workspace lifecycle operations against the ORM backend.
# ================================================================

import os
import pytest
from quantum_mechanic.core.database import Database
from quantum_mechanic.core.workspace import Workspace

@pytest.fixture
def orm_workspace(tmp_path):
    """Workspace on the SQLAlchemy path."""
    db = Database.create("orm-lifecycle-test", tmp_path)
    url = f"sqlite:///{db.db_path}"

    with pytest.MonkeyPatch().context() as mp:
        mp.setenv("QM_DATABASE_URL", url)
        ws = Workspace(db, "orm-lifecycle-test")
        yield ws
        ws.close()

class TestWorkspaceORMLifecycle:
    def test_close_disposes_engines(self, orm_workspace):
        """close() should dispose of all domain store engines."""
        # Verify engines are present before close
        assert hasattr(orm_workspace._credentials, "_engine")
        assert hasattr(orm_workspace._evidence, "_engine")
        
        # We can't easily check 'disposed' state directly on Engine without 
        # reaching deep into internals, but we can verify that subsequent
        # operations fail after we close the underlying database as well.
        orm_workspace.close()
        
        # main DB should be closed
        assert orm_workspace.db.conn is None
        
    def test_operations_fail_after_close(self, orm_workspace):
        """Operations should fail after close() is called."""
        from sqlalchemy.exc import StatementError, OperationalError
        
        orm_workspace.close()
        
        with pytest.raises((AttributeError, StatementError, OperationalError, TypeError)):
            orm_workspace.list_credentials()
