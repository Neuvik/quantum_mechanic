# ================================================================
# MODULE: quantum_mechanic.providers.entra.arm_credential
# ----------------------------------------------------------------
# PURPOSE:   Azure SDK TokenCredential backed by EntraTokenStore.
#
#            Bridges Entra-sourced ARM tokens (via FOCI expansion)
#            into the Azure SDK credential contract. Allows all
#            Azure SDK techniques (which call get_token()) to work
#            with credentials obtained from the Entra pipeline.
# ================================================================

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from quantum_mechanic.providers.entra.token_store import EntraTokenStore

logger = logging.getLogger(__name__)

_DEFAULT_RESOURCE = "https://management.azure.com"


class EntraTokenCredential:
    """Azure SDK TokenCredential backed by an EntraTokenStore.

    Implements the minimal Azure SDK credential contract so that
    azure.mgmt.* clients work with tokens sourced from Entra FOCI.
    """

    def __init__(self, store: EntraTokenStore) -> None:
        self._store = store

    def get_token(self, *scopes: str, **kwargs) -> object:
        """Return an AccessToken for the requested scope.

        Azure SDK passes scopes like 'https://management.azure.com/.default'.
        We strip the '/.default' suffix to get the resource URI, then look
        up or expand to an access token in the store.
        """
        from azure.core.credentials import AccessToken

        resource = _scope_to_resource(scopes[0] if scopes else _DEFAULT_RESOURCE)

        tok = self._store.best_token(resource)
        if tok is None or tok.token_type == "refresh_token":
            from quantum_mechanic.providers.entra.foci import foci_expand
            tok = foci_expand(self._store, resource)

        if tok is None:
            raise ValueError(
                f"No ARM token available for {resource}. "
                "Run: acquire entra arm"
            )

        expires_on = (
            int(tok.expires_at.timestamp())
            if tok.expires_at
            else int(time.time()) + 3600
        )
        return AccessToken(tok.value, expires_on)

    def get_token_info(self, *scopes: str, **kwargs) -> object:
        """Azure SDK v2 compat — delegates to get_token."""
        return self.get_token(*scopes, **kwargs)


def _scope_to_resource(scope: str) -> str:
    """Convert an Azure SDK scope URI to an ARM resource URI.

    'https://management.azure.com/.default' → 'https://management.azure.com'
    'https://management.azure.com'          → 'https://management.azure.com'
    """
    if scope.endswith("/.default"):
        return scope[: -len("/.default")]
    return scope.rstrip("/")
