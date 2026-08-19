# ================================================================
# MODULE: quantum_mechanic.providers.entra.refs
# ----------------------------------------------------------------
# PURPOSE:   Loader for vendored Entra ID reference data — Microsoft
#            first-party client IDs, FOCI/BROCI family membership,
#            pre-consented Graph permissions, display-name lookup.
#
# UPSTREAM:  See README.md in this directory for full attribution
#            (zh54321/GraphPreConsentExplorer, merill/microsoft-info).
#            The data itself is community-maintained; QM vendors it
#            so detectors work fully offline during engagements.
#
# RESILIENCE: If either file is missing (fresh clone before deps,
#            corrupted checkout), loaders fall back to an in-code
#            baseline dict of ~7 well-known FOCI clients so nothing
#            imports-breaks. Callers get a small subset instead of a
#            wall of ImportError.
# ================================================================

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_REFS_DIR = Path(__file__).parent
_GRAPH_PRECONSENT_PATH = _REFS_DIR / "GraphPreConsent.yaml"
_MICROSOFT_APPS_PATH = _REFS_DIR / "MicrosoftApps.json"


# In-code baseline used when the vendored files are missing. Same 7 clients
# that were previously hardcoded in providers/entra/foci.py — keeps a fresh
# clone or corrupt checkout bootable while surfacing a WARNING so the
# missing refs get noticed.
_BASELINE_FOCI: dict[str, str] = {
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "4765445b-32c6-49b0-83e6-1d93765276ca": "Office Web",
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "4345a7b9-9a63-4910-a426-35363201d503": "O365 Shell Mobile",
}


# ----------------------------------------------------------------
# Raw loaders — cached, one filesystem read per process.
# ----------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_graph_preconsent() -> list[dict[str, Any]]:
    """Load the GraphPreConsent YAML. Returns [] on any error."""
    if not _GRAPH_PRECONSENT_PATH.exists():
        logger.warning(
            "Entra refs missing: %s. Detectors will fall back to a small "
            "baseline FOCI list. Refresh the vendored Entra reference data to restore full coverage.",
            _GRAPH_PRECONSENT_PATH,
        )
        return []
    try:
        import yaml
    except ImportError:
        logger.warning(
            "PyYAML not installed — cannot load %s. `uv sync` should install it.",
            _GRAPH_PRECONSENT_PATH,
        )
        return []
    try:
        data = yaml.safe_load(_GRAPH_PRECONSENT_PATH.read_text())
        apps = data.get("apps", []) if isinstance(data, dict) else []
        return [a for a in apps if isinstance(a, dict)]
    except Exception as e:  # pragma: no cover — file-corruption path
        logger.warning("Failed to parse %s: %s", _GRAPH_PRECONSENT_PATH, e)
        return []


@lru_cache(maxsize=1)
def _load_microsoft_apps() -> list[dict[str, Any]]:
    """Load the MicrosoftApps JSON. Returns [] on any error."""
    if not _MICROSOFT_APPS_PATH.exists():
        logger.warning("Entra refs missing: %s.", _MICROSOFT_APPS_PATH)
        return []
    try:
        data = json.loads(_MICROSOFT_APPS_PATH.read_text())
        return [e for e in data if isinstance(e, dict)]
    except Exception as e:  # pragma: no cover
        logger.warning("Failed to parse %s: %s", _MICROSOFT_APPS_PATH, e)
        return []


# ----------------------------------------------------------------
# Public accessors — the surface detectors and other callers use.
# ----------------------------------------------------------------


def foci_client_ids() -> dict[str, str]:
    """Return {client_id: name} for every FOCI-flagged first-party client.

    Falls back to the in-code baseline (7 well-known clients) if the
    vendored YAML is missing.
    """
    apps = _load_graph_preconsent()
    if not apps:
        return dict(_BASELINE_FOCI)
    out: dict[str, str] = {}
    for a in apps:
        if str(a.get("foci", "")).lower() == "true":
            cid = a.get("client_id")
            if cid:
                out[cid] = a.get("name", cid)
    # Union in the baseline so we never regress below the historical set,
    # even if upstream ever drops a well-known ID by mistake.
    for cid, name in _BASELINE_FOCI.items():
        out.setdefault(cid, name)
    return out


def broci_client_ids() -> dict[str, str]:
    """Return {client_id: name} for every BROCI-flagged client.

    BROCI (Broker of Client IDs) is a related token-broker attack primitive
    — apps that broker tokens for other clients. Currently used by the
    (future) detect_broci_exclusion_blast detector.
    """
    apps = _load_graph_preconsent()
    out: dict[str, str] = {}
    for a in apps:
        if str(a.get("broci", "")).lower() == "true":
            cid = a.get("client_id")
            if cid:
                out[cid] = a.get("name", cid)
    return out


def device_code_enabled_clients() -> dict[str, str]:
    """Return {client_id: name} for every client with device_code auth."""
    apps = _load_graph_preconsent()
    out: dict[str, str] = {}
    for a in apps:
        if str(a.get("device_code", "")).lower() == "true":
            cid = a.get("client_id")
            if cid:
                out[cid] = a.get("name", cid)
    return out


def client_preconsented_graph_perms(client_id: str) -> list[str]:
    """Return the pre-consented Graph permissions for a first-party client,
    or [] if the client is unknown or has no pre-consent entry."""
    for a in _load_graph_preconsent():
        if a.get("client_id") == client_id:
            perms = a.get("graph_api_permissions", [])
            return list(perms) if isinstance(perms, list) else []
    return []


def app_display_name(client_id: str) -> str | None:
    """Resolve a Microsoft first-party client_id to a human display name.

    Consults GraphPreConsent (richer metadata) first, then MicrosoftApps
    (broader coverage). Returns None if unknown so callers can fall
    through to the raw GUID.
    """
    for a in _load_graph_preconsent():
        if a.get("client_id") == client_id:
            return a.get("name")
    for a in _load_microsoft_apps():
        if a.get("AppId") == client_id:
            return a.get("AppDisplayName")
    return None


def refs_status() -> dict[str, Any]:
    """Diagnostic status of the vendored files — used by the shell
    `refs status entra` command and by attribution footers in detector
    output."""
    gpce = _load_graph_preconsent()
    ma = _load_microsoft_apps()
    return {
        "graph_preconsent": {
            "path": str(_GRAPH_PRECONSENT_PATH),
            "present": _GRAPH_PRECONSENT_PATH.exists(),
            "app_count": len(gpce),
            "foci_count": sum(1 for a in gpce if str(a.get("foci", "")).lower() == "true"),
            "broci_count": sum(1 for a in gpce if str(a.get("broci", "")).lower() == "true"),
        },
        "microsoft_apps": {
            "path": str(_MICROSOFT_APPS_PATH),
            "present": _MICROSOFT_APPS_PATH.exists(),
            "app_count": len(ma),
        },
    }


ATTRIBUTION_LINE = (
    "FOCI list sourced from zh54321/GraphPreConsentExplorer (MIT). "
    "App-name lookup from merill/microsoft-info (MIT). "
    "See providers/entra/refs/README.md for interactive browsers."
)
