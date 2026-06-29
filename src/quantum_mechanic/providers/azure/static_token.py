"""StaticTokenCredential — a TokenCredential that returns ONLY a stored token.

Used by Azure auth paths that captured a token at import time. The credential
never falls back to local state (no DefaultAzureCredential, no az CLI cache).

When the token expires, get_token raises a clean error — the operator must
re-import the credential to obtain a fresh token. This is intentional: a
captured-at-import credential cannot silently refresh from local state, because
that's exactly the bug class this class exists to prevent.
"""
from __future__ import annotations

import time

from azure.core.credentials import AccessToken


class StaticTokenCredential:
    """TokenCredential implementation that returns only a stored access token.

    Implements the `azure.core.credentials.TokenCredential` protocol
    (duck-typed — Azure SDK clients just call .get_token(*scopes)).
    """

    def __init__(self, *, access_token: str, expires_on: int) -> None:
        self._token = access_token
        self._expires_on = expires_on

    def get_token(self, *scopes: str, **kwargs) -> AccessToken:
        """Return the stored token. Ignores the scope argument by design."""
        if time.time() >= self._expires_on:
            raise RuntimeError(
                "Stored Azure credential has expired. "
                "Re-import the credential to capture a fresh token "
                "(import azure --default) or use a service-principal credential."
            )
        return AccessToken(token=self._token, expires_on=self._expires_on)
