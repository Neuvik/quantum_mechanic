"""Tests for `import azure --default` capture-at-import path."""
import base64
import json
from unittest.mock import MagicMock, patch

from quantum_mechanic.shell.commands import _import_azure


def _fake_jwt(upn: str, oid: str, tid: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"upn": upn, "oid": oid, "tid": tid}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_import_azure_default_captures_token_not_method_reference():
    """OUTCOME: import azure --default stores access_token, not {'method':'default'}.

    ANTI-GAMIFICATION: We assert on the EXACT secret dict shape passed to
    _validate_and_import. If anyone reintroduces a method:default placeholder,
    this test fails immediately.
    """
    state = MagicMock()
    opts = {"default": "true"}

    fake_token = MagicMock()
    fake_token.token = _fake_jwt("alice@contoso.com", "oid-1", "tid-1")
    fake_token.expires_on = 9999999999

    with patch("quantum_mechanic.shell.commands._validate_and_import") as mock_validate, \
         patch("azure.identity.DefaultAzureCredential") as mock_cred:
        mock_cred.return_value.get_token.return_value = fake_token
        _import_azure(state, opts)

    mock_validate.assert_called_once()
    args = mock_validate.call_args.args
    # args order: (state, provider, cred_type, secret, friendly)
    secret = args[3]
    assert secret["method"] == "captured_token", (
        f"Storage MUST use captured_token, got method={secret.get('method')!r}"
    )
    assert secret["access_token"] == fake_token.token
    assert secret["captured_principal"] == "alice@contoso.com"
    assert "default" not in secret.get("method", ""), (
        "Storage must not contain 'default' anywhere — that's the bug shape"
    )


def test_import_azure_service_principal_still_works():
    """OUTCOME: import azure with --client-id flow remains unchanged."""
    state = MagicMock()
    opts = {
        "client-id": "client-uuid",
        "client-secret": "secret",
        "tenant-id": "tenant-uuid",
    }

    with patch("quantum_mechanic.shell.commands._validate_and_import") as mock_validate:
        _import_azure(state, opts)

    args = mock_validate.call_args.args
    secret = args[3]
    cred_type = args[2]
    assert cred_type == "service_principal"
    assert secret["tenant_id"] == "tenant-uuid"
    assert secret["client_id"] == "client-uuid"
    assert secret["client_secret"] == "secret"
