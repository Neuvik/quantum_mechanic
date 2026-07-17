"""Tests for the vendored Entra refs loader.

Guards:
- foci_client_ids() returns the full community list, not the 7-app baseline
- Baseline is used as fallback when the file is missing (fresh-clone safety)
- Baseline entries are never dropped even if upstream misses them
- broci_client_ids() / device_code_enabled_clients() / app_display_name()
  all read from the vendored file
- ATTRIBUTION_LINE names both upstream projects (regression guard on the
  credit obligation)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from quantum_mechanic.providers.entra import refs


def test_foci_client_ids_returns_more_than_baseline():
    """OUTCOME: With the vendored YAML present, we get 40+ FOCI apps —
    dramatically more than the 7-app hardcoded baseline. This is the
    whole point of vendoring.
    """
    ids = refs.foci_client_ids()
    assert len(ids) > 40, (
        f"Expected 40+ FOCI clients from vendored data, got {len(ids)}. "
        "Refs file may be missing — run tools/update_entra_refs.py."
    )
    # And every entry is (guid → name) shaped.
    for cid, name in ids.items():
        assert isinstance(cid, str) and len(cid) == 36
        assert isinstance(name, str) and name


def test_foci_client_ids_always_includes_baseline_apps():
    """OUTCOME: Even if upstream ever drops a well-known ID, we never lose
    the 7 apps QM has depended on since v0.1.0."""
    ids = refs.foci_client_ids()
    for cid, name in refs._BASELINE_FOCI.items():
        assert cid in ids, f"Baseline FOCI app {cid} ({name}) missing from load"


def test_foci_client_ids_falls_back_to_baseline_when_file_missing():
    """OUTCOME: A fresh clone where the vendored YAML hasn't been fetched
    still imports and gets a usable (7-app) list, plus a warning in logs."""
    refs._load_graph_preconsent.cache_clear()
    with patch.object(refs, "_GRAPH_PRECONSENT_PATH", Path("/nonexistent/gpce.yaml")):
        ids = refs.foci_client_ids()
    # Reset for other tests.
    refs._load_graph_preconsent.cache_clear()
    assert ids == refs._BASELINE_FOCI


def test_broci_client_ids_populated():
    """OUTCOME: BROCI list surfaces from vendored data (100+ clients)."""
    ids = refs.broci_client_ids()
    assert len(ids) > 50, f"Expected 50+ BROCI clients, got {len(ids)}"


def test_device_code_enabled_clients_populated():
    """OUTCOME: device_code list has 100+ entries (matches upstream reality)."""
    ids = refs.device_code_enabled_clients()
    assert len(ids) > 100


def test_app_display_name_resolves_known_foci_app():
    """OUTCOME: Microsoft Office's GUID resolves to a real name string."""
    name = refs.app_display_name("d3590ed6-52b3-4102-aeff-aad2292ab01c")
    assert name is not None
    assert "Office" in name


def test_app_display_name_returns_none_for_unknown_guid():
    """OUTCOME: Genuinely unknown GUIDs return None (caller falls through to raw).

    Uses a v4 UUID unlikely to ever be assigned to a real MS first-party app.
    (Amusing gotcha: the all-zeros GUID IS in the vendored data as "Designated
    empty GUID" — Microsoft catalogs it too.)
    """
    assert refs.app_display_name("deadbeef-1337-4c0d-b00c-facef00dbabe") is None


def test_client_preconsented_graph_perms_returns_list_for_known_client():
    """OUTCOME: Known first-party client → its pre-consented Graph perm list."""
    perms = refs.client_preconsented_graph_perms(
        "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office
    )
    assert isinstance(perms, list)
    # Microsoft Office's baseline preconsent set is non-trivial.
    assert len(perms) >= 5


def test_refs_status_reports_health():
    """OUTCOME: refs_status() diagnostic includes counts + paths."""
    status = refs.refs_status()
    assert status["graph_preconsent"]["present"] is True
    assert status["graph_preconsent"]["foci_count"] > 40
    assert status["microsoft_apps"]["present"] is True
    assert status["microsoft_apps"]["app_count"] > 1000


def test_attribution_line_credits_both_upstream_projects():
    """ANTI-GAMIFICATION: The attribution string must always name both
    upstream projects. If someone strips it to save characters or forgets
    one, this test fails — vendored MIT-licensed data comes with credit
    obligations that must not silently regress."""
    line = refs.ATTRIBUTION_LINE
    assert "zh54321" in line or "GraphPreConsentExplorer" in line
    assert "merill" in line or "microsoft-info" in line
    assert "MIT" in line


def test_foci_module_dict_matches_refs_loader():
    """OUTCOME: providers/entra/foci.py::FOCI_CLIENT_IDS is populated from
    the refs loader — not still hardcoded to 7 apps."""
    from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS
    assert len(FOCI_CLIENT_IDS) > 40, (
        f"foci.py::FOCI_CLIENT_IDS still hardcoded — got only "
        f"{len(FOCI_CLIENT_IDS)} entries. Vendoring is not wired up."
    )
