import csv
from pathlib import Path
import pytest
from quantum_mechanic.core.loot import loot_writer
from quantum_mechanic.core.runner import TechniqueResult

# Mock a technique module metadata via sys.modules so imports succeed in LootWriter
import sys
from types import ModuleType

@pytest.fixture(autouse=True)
def mock_technique_module():
    mod = ModuleType("quantum_mechanic.techniques.discovery.test_mock_tech")
    mod.LOOT_ITEMS_KEY = "items"
    mod.LOOT_SCHEMA = [
        ("id", "ID", "bold"),
        ("name", "Name", "cyan"),
        ("notes", None, None),
    ]
    sys.modules["quantum_mechanic.techniques.discovery.test_mock_tech"] = mod
    yield
    if "quantum_mechanic.techniques.discovery.test_mock_tech" in sys.modules:
        del sys.modules["quantum_mechanic.techniques.discovery.test_mock_tech"]

def test_loot_writer_overwrites_on_empty(tmp_path):
    db_path = tmp_path / "workspaces" / "test.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.touch()

    loot_dir = db_path.parent / "test" / "loot" / "discovery" / "test_mock_tech"

    # Run 1: Returns items
    res_1 = TechniqueResult(
        technique_id="discovery/test_mock_tech",
        provider="aws",
        status="success",
        data={"items": [{"id": "1", "name": "Alice"}]},
        params={},
    )
    loot_writer.write(res_1, db_path)

    csv_file = loot_dir / "loot.csv"
    tbl_file = loot_dir / "table.txt"

    assert csv_file.exists()
    assert tbl_file.exists()

    with csv_file.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["id"] == "1"

    original_table_content = tbl_file.read_text(encoding="utf-8")
    assert "Alice" in original_table_content

    # Run 2: Empty/Zero items
    res_2 = TechniqueResult(
        technique_id="discovery/test_mock_tech",
        provider="aws",
        status="success",
        data={"items": []},
        params={},
    )
    loot_writer.write(res_2, db_path)

    # Both files must be overwritten
    with csv_file.open(newline="", encoding="utf-8") as fh:
        rows_empty = list(csv.DictReader(fh))
    assert len(rows_empty) == 0

    new_table_content = tbl_file.read_text(encoding="utf-8")
    assert "Alice" not in new_table_content
    assert "ID" in new_table_content  # Still has headers


# --------------------------------------------------------------------
# Phase A6: Loot writer honors status field.
# When status is 'denied' or 'error', we MUST NOT write misleading
# empty loot.csv / table.txt — instead drop a _status.txt sentinel.
# --------------------------------------------------------------------

def _make_db(tmp_path):
    db_path = tmp_path / "workspaces" / "test.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.touch()
    return db_path


def test_loot_writer_skips_csv_on_denied_status(tmp_path):
    """OUTCOME: status='denied' → no loot.csv, no table.txt, only _status.txt.

    ANTI-GAMIFICATION: If someone regresses this, operators grepping loot
    dirs after a 403 will find empty CSVs that look like a real "0 results"
    finding — the whole class of bug Phase A eliminates.
    """
    db_path = _make_db(tmp_path)
    loot_dir = db_path.parent / "test" / "loot" / "discovery" / "test_mock_tech"

    res = TechniqueResult(
        technique_id="discovery/test_mock_tech",
        provider="entra",
        status="denied",
        data={
            "error": "HTTP 403 on /users",
            "required_scope": "User.Read.All",
            "http_status": 403,
        },
        error="HTTP 403 on /users",
    )
    loot_writer.write(res, db_path)

    assert not (loot_dir / "loot.csv").exists(), "denied runs must not emit loot.csv"
    assert not (loot_dir / "table.txt").exists(), "denied runs must not emit table.txt"
    status_txt = loot_dir / "_status.txt"
    assert status_txt.exists(), "denied runs must emit _status.txt sentinel"
    content = status_txt.read_text()
    assert "status: denied" in content
    assert "User.Read.All" in content
    assert "403" in content


def test_loot_writer_skips_csv_on_error_status(tmp_path):
    """OUTCOME: status='error' → same skip behavior as denied."""
    db_path = _make_db(tmp_path)
    loot_dir = db_path.parent / "test" / "loot" / "discovery" / "test_mock_tech"

    res = TechniqueResult(
        technique_id="discovery/test_mock_tech",
        provider="entra",
        status="error",
        data={"error": "Backend 503"},
        error="Backend 503",
    )
    loot_writer.write(res, db_path)

    assert not (loot_dir / "loot.csv").exists()
    assert (loot_dir / "_status.txt").exists()
    assert "status: error" in (loot_dir / "_status.txt").read_text()


def test_loot_writer_still_writes_csv_on_partial_status_with_note(tmp_path):
    """OUTCOME: status='partial' → CSV IS written (data is real), AND a
    _status.txt is emitted noting the partial nature so operators know
    to re-run to close the gap."""
    db_path = _make_db(tmp_path)
    loot_dir = db_path.parent / "test" / "loot" / "discovery" / "test_mock_tech"

    res = TechniqueResult(
        technique_id="discovery/test_mock_tech",
        provider="entra",
        status="partial",
        data={"items": [{"id": "1", "name": "Bob"}]},
    )
    loot_writer.write(res, db_path)

    assert (loot_dir / "loot.csv").exists(), "partial runs still emit CSV — data is real"
    assert (loot_dir / "table.txt").exists()
    assert (loot_dir / "_status.txt").exists()
    assert "status: partial" in (loot_dir / "_status.txt").read_text()
