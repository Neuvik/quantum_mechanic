"""Graph permission UUID → human-readable name resolver.

Resource service principals (e.g. Microsoft Graph itself) expose their
permission catalog via two fields on the `/servicePrincipals(appId='...')`
endpoint:

- `appRoles[]`               — Application permissions (perm.type=="Role")
- `oauth2PermissionScopes[]` — Delegated permissions  (perm.type=="Scope")

Each entry has an `id` (UUID) and a `value` (the human-readable perm name
that EAM classification uses, e.g. `RoleManagement.ReadWrite.Directory`).

The resolver caches the per-resource lookup in memory for the session so
each Graph SP is fetched at most once per technique run.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GraphPermResolver:
    """Resolve Graph permission UUIDs to human-readable names.

    Args:
        http: An open `httpx.Client` (caller manages lifetime).
        headers: Headers including `Authorization: Bearer <graph-token>`.
    """

    def __init__(self, *, http: httpx.Client, headers: dict[str, str]) -> None:
        self._http = http
        self._headers = headers
        # cache: resource_app_id -> ({role_id: name}, {scope_id: name})
        self._cache: dict[str, tuple[dict[str, str], dict[str, str]]] = {}

    def resolve_perm_names(
        self,
        resource_app_id: str,
        perm_entries: list[dict[str, Any]],
    ) -> list[str]:
        """Resolve a list of perm entries to human-readable names.

        Args:
            resource_app_id: The resource SP's appId (e.g. Graph = `0000...c000-...`).
            perm_entries: Items from `requiredResourceAccess[].resourceAccess[]`
                shaped like `{"id": "<uuid>", "type": "Role" | "Scope"}`.

        Returns:
            List of resolved permission names. Unknown UUIDs are dropped.
        """
        if not perm_entries:
            return []

        roles, scopes = self._lookup(resource_app_id)
        out: list[str] = []
        for entry in perm_entries:
            uuid = entry.get("id")
            ptype = entry.get("type")
            if not uuid:
                continue
            if ptype == "Role":
                name = roles.get(uuid)
            elif ptype == "Scope":
                name = scopes.get(uuid)
            else:
                name = None
            if name:
                out.append(name)
        return out

    def _lookup(self, resource_app_id: str) -> tuple[dict[str, str], dict[str, str]]:
        """Fetch and cache (role_id→name, scope_id→name) for a resource app."""
        if resource_app_id in self._cache:
            return self._cache[resource_app_id]

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter=appId eq '{resource_app_id}'"
            "&$select=id,appId,appRoles,oauth2PermissionScopes"
        )
        try:
            resp = self._http.get(url, headers=self._headers)
            if resp.status_code != 200:
                logger.debug("graph_perms: %s returned HTTP %d", resource_app_id, resp.status_code)
                self._cache[resource_app_id] = ({}, {})
                return self._cache[resource_app_id]
            body = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            logger.debug("graph_perms: resolver fetch failed for %s: %s", resource_app_id, e)
            self._cache[resource_app_id] = ({}, {})
            return self._cache[resource_app_id]

        sps = body.get("value", [])
        if not sps:
            self._cache[resource_app_id] = ({}, {})
            return self._cache[resource_app_id]

        sp = sps[0]
        roles = {r["id"]: r["value"] for r in sp.get("appRoles", []) if "id" in r and "value" in r}
        scopes = {
            s["id"]: s["value"]
            for s in sp.get("oauth2PermissionScopes", [])
            if "id" in s and "value" in s
        }
        self._cache[resource_app_id] = (roles, scopes)
        return self._cache[resource_app_id]
