# ================================================================
# MODULE: quantum_mechanic.providers.entra.graph
# ----------------------------------------------------------------
# PURPOSE:   Thin Graph API helpers shared across entra techniques.
#
#            graph_list() handles paginated GET requests — Graph
#            returns up to $top items per page, with @odata.nextLink
#            pointing to the next page.
# ================================================================

from __future__ import annotations

from typing import Any

import httpx


def graph_list(
    http: httpx.Client,
    url: str,
    headers: dict[str, str],
    max_pages: int = 20,
) -> list[dict[str, Any]]:
    """Fetch all pages of a Graph list endpoint.

    Args:
        http:      Caller-managed httpx.Client.
        url:       Initial Graph URL (may include $top, $select, $filter).
        headers:   Auth headers (Authorization: Bearer ...).
        max_pages: Safety cap on pages fetched (default 20 × $top items).

    Returns:
        Flat list of all items from the "value" array across all pages.
    """
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    pages = 0

    while next_url and pages < max_pages:
        resp = http.get(next_url, headers=headers)
        if resp.status_code != 200:
            break
        body = resp.json()
        items.extend(body.get("value", []))
        next_url = body.get("@odata.nextLink")
        pages += 1

    return items
