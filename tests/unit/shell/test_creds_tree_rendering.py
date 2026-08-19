"""Tests for Part 3: lineage rendering in `creds` output.

Design choice: no tree glyphs in the ID column (that made numbers awkward
to scan and misaligned). Instead, children are sorted immediately after
their parent, and each derived row's Identity cell carries a dim
`from #N` suffix. The ID column stays a clean right-aligned integer.
"""
from __future__ import annotations

from io import StringIO

from rich.console import Console

from quantum_mechanic.shell import formatters as f
from quantum_mechanic.shell.formatters import _sort_creds_by_lineage


def _capture(fn, *args) -> str:
    buf = StringIO()
    fake = Console(file=buf, force_terminal=False, color_system=None, width=200)
    orig = f.console
    f.console = fake
    try:
        fn(*args)
    finally:
        f.console = orig
    return buf.getvalue()


def test_sort_places_children_after_parent():
    """OUTCOME: A child cred always sorts immediately after its parent, regardless
    of insertion order in the raw list."""
    creds = [
        {"id": 3, "derived_from_id": 1, "provider": "entra"},
        {"id": 1, "derived_from_id": None, "provider": "entra"},
        {"id": 2, "derived_from_id": None, "provider": "entra"},
        {"id": 4, "derived_from_id": 3, "provider": "entra"},
    ]
    ordered = _sort_creds_by_lineage(creds)
    ids = [c["id"] for c in ordered]
    # #1 root, then its chain #3 → #4, then unrelated root #2.
    assert ids == [1, 3, 4, 2]


def test_sort_orphan_child_falls_through_as_root():
    """OUTCOME: A cred whose parent isn't in the list renders as a root
    (rather than getting dropped)."""
    creds = [
        {"id": 5, "derived_from_id": 99, "provider": "entra"},  # parent #99 not in list
        {"id": 1, "derived_from_id": None, "provider": "entra"},
    ]
    ordered = _sort_creds_by_lineage(creds)
    ids = {c["id"] for c in ordered}
    assert ids == {1, 5}, "orphaned children must not disappear"


def test_derived_row_shows_from_parent_marker():
    """OUTCOME: A derived cred's Identity cell contains `from #N`, and the
    ID column stays a clean number (no └─ glyph)."""
    creds = [
        {
            "id": 1, "provider": "entra", "credential_type": "token_store",
            "friendly_name": "alice@x.example", "status": "active",
            "derived_from_id": None,
        },
        {
            "id": 2, "provider": "entra", "credential_type": "token_store",
            "friendly_name": "alice@x.example → ARM", "status": "active",
            "derived_from_id": 1,
        },
    ]
    out = _capture(f.format_credentials, creds)
    assert "from #1" in out, "child rows must carry a `from #N` parent marker"
    assert "└─" not in out, "no tree glyphs — that caused the alignment issue"


def test_hint_mentions_from_convention_when_lineage_exists():
    """OUTCOME: When at least one derived cred is present, the hint explains
    what `from #N` means."""
    creds = [
        {"id": 1, "provider": "entra", "credential_type": "token_store",
         "friendly_name": "alice@x.example", "status": "active",
         "derived_from_id": None},
        {"id": 2, "provider": "entra", "credential_type": "token_store",
         "friendly_name": "alice@x.example → ARM", "status": "active",
         "derived_from_id": 1},
    ]
    out = _capture(f.format_credentials, creds)
    assert "from #N" in out or "parent" in out.lower()


def test_no_from_marker_on_flat_cred_list():
    """OUTCOME: A flat cred list shows no `from #N` — feature only surfaces
    when there's actually a pivot chain to represent."""
    creds = [
        {"id": 1, "provider": "entra", "credential_type": "token_store",
         "friendly_name": "alice@x.example", "status": "active",
         "derived_from_id": None},
    ]
    out = _capture(f.format_credentials, creds)
    assert "from #" not in out
