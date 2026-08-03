"""Tests for `workspace delete` — the missing subcommand regression.

Covers:
- Deletes the .db file
- Deletes the sibling <name>/ artifact directory (loot, exports)
- Raises FileNotFoundError for a non-existent workspace
- Does not touch UNRELATED workspaces
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from quantum_mechanic.core.workspace import Workspace


def test_delete_removes_db_file():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        ws = Workspace.create("target", workspace_dir=base)
        ws.close()
        db_path = base / "target.db"
        assert db_path.exists()

        Workspace.delete("target", workspace_dir=base)
        assert not db_path.exists()


def test_delete_removes_sibling_artifact_dir():
    """OUTCOME: The <name>/ directory that holds loot and BloodHound exports
    is removed alongside the .db.

    ANTI-GAMIFICATION: If someone regresses this and only removes the .db,
    the workspace list looks clean but the artifact tree lingers on disk
    with the operator's engagement loot.
    """
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        ws = Workspace.create("target", workspace_dir=base)
        ws.close()

        # Simulate loot writer + BloodHound export having landed here.
        artifact_dir = base / "target"
        (artifact_dir / "loot" / "discovery" / "entra_enum_users").mkdir(parents=True)
        (artifact_dir / "loot" / "discovery" / "entra_enum_users" / "loot.csv").write_text("id\n1\n")
        (artifact_dir / "bloodhound.json").write_text("{}")
        assert artifact_dir.exists()

        Workspace.delete("target", workspace_dir=base)
        assert not artifact_dir.exists()


def test_delete_missing_workspace_raises_file_not_found():
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(FileNotFoundError, match="ghost"):
            Workspace.delete("ghost", workspace_dir=Path(td))


def test_delete_leaves_unrelated_workspaces_intact():
    """OUTCOME: Deleting 'a' must not touch 'b' or its artifact dir."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        Workspace.create("a", workspace_dir=base).close()
        Workspace.create("b", workspace_dir=base).close()
        (base / "b").mkdir(exist_ok=True)
        (base / "b" / "loot.csv").write_text("keep me")

        Workspace.delete("a", workspace_dir=base)

        assert not (base / "a.db").exists()
        assert (base / "b.db").exists()
        assert (base / "b" / "loot.csv").exists()


def test_delete_leaves_artifact_dir_alone_when_it_does_not_exist():
    """OUTCOME: No artifact dir → delete still succeeds (idempotent on the
    directory side)."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        Workspace.create("clean", workspace_dir=base).close()
        # Deliberately do not create the sibling dir.
        Workspace.delete("clean", workspace_dir=base)  # must not raise
        assert not (base / "clean.db").exists()
