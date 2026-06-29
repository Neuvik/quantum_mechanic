"""Tests for StaticTokenCredential — no fallback to local state."""
import pytest

from quantum_mechanic.providers.azure.static_token import StaticTokenCredential


def test_returns_stored_token():
    """OUTCOME: get_token returns the stored access token verbatim."""
    cred = StaticTokenCredential(access_token="abc.def.ghi", expires_on=9999999999)
    result = cred.get_token("https://management.azure.com/.default")
    assert result.token == "abc.def.ghi"
    assert result.expires_on == 9999999999


def test_expired_token_raises():
    """OUTCOME: an expired token raises a clean error pointing operator to re-import."""
    cred = StaticTokenCredential(access_token="x", expires_on=0)
    with pytest.raises(RuntimeError, match="expired"):
        cred.get_token("https://management.azure.com/.default")


def test_ignores_scope_argument():
    """OUTCOME: get_token always returns the same token regardless of scope requested.

    Static tokens are scope-locked at acquisition time; the resource argument
    is ignored. This is deliberate — there's nowhere to mint additional scopes.
    """
    cred = StaticTokenCredential(access_token="abc", expires_on=9999999999)
    t1 = cred.get_token("https://management.azure.com/.default")
    t2 = cred.get_token("https://graph.microsoft.com/.default")
    assert t1.token == t2.token == "abc"
