# ================================================================
# MODULE: quantum_mechanic.providers.entra.arm
# ----------------------------------------------------------------
# PURPOSE:   ARM (Azure Resource Manager) REST API helpers.
#
#            ARM pagination uses 'nextLink' (bare URL, not the
#            '@odata.nextLink' prefix used by Microsoft Graph).
#            This module mirrors providers/entra/graph.py for the
#            ARM surface.
# ================================================================

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)


def arm_list(
    http: httpx.Client,
    url: str,
    headers: dict[str, str],
    max_pages: int = 20,
) -> list[dict]:
    """Paginate an ARM list endpoint and return all items.

    ARM responses use 'nextLink' (not '@odata.nextLink').
    Stops silently on non-200 or when nextLink is absent.
    """
    items: list[dict] = []
    next_url: str | None = url
    pages = 0

    while next_url and pages < max_pages:
        resp = http.get(next_url, headers=headers)
        if resp.status_code != 200:
            logger.debug(
                "arm_list: non-200 from %s: %d %s",
                next_url,
                resp.status_code,
                resp.text[:200],
            )
            break
        body = resp.json()
        items.extend(body.get("value", []))
        next_url = body.get("nextLink")
        pages += 1

    return items
