from unittest.mock import MagicMock, patch

from quantum_mechanic.techniques.collection.get_secrets import execute


def _ctx(
    provider: str = "gcp",
    *,
    account_id: str = "proj-default",
    target: str | None = None,
    secret_name: str | None = None,
) -> MagicMock:
    ctx = MagicMock()
    ctx.provider_name = provider
    ctx.session = MagicMock()

    def _get_param(name: str, default=None):
        if name == "target":
            return target
        if name == "secret_name":
            return secret_name
        return default

    ctx.get_param.side_effect = _get_param
    ctx.whoami.return_value = MagicMock(account_id=account_id)
    return ctx


class TestGetSecretsGCP:
    def test_unknown_provider_returns_error(self):
        result = execute(_ctx(provider="entra"))
        assert "error" in result
        assert "secrets" in result

    def test_import_guard_returns_error(self):
        with (
            patch("quantum_mechanic.techniques.collection.get_secrets.secretmanager", None),
            patch("quantum_mechanic.techniques.collection.get_secrets.resourcemanager_v3", None),
        ):
            result = execute(_ctx())

        assert "error" in result
        assert "google-cloud-secret-manager" in result["error"]

    def test_retrieves_secret_values_from_secret_manager(self):
        ctx = _ctx(secret_name="db-password")
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.return_value = [MagicMock(project_id="proj-1")]

        mock_secretmanager = MagicMock()
        mock_client = mock_secretmanager.SecretManagerServiceClient.return_value

        secret = MagicMock()
        secret.name = "projects/proj-1/secrets/db-password"
        secret.annotations = {"content_type": "text/plain"}
        mock_client.list_secrets.return_value = [secret]

        version = MagicMock()
        version.payload.data = b"super-secret"
        mock_client.access_secret_version.return_value = version

        with (
            patch(
                "quantum_mechanic.techniques.collection.get_secrets.resourcemanager_v3",
                mock_rm,
            ),
            patch(
                "quantum_mechanic.techniques.collection.get_secrets.secretmanager",
                mock_secretmanager,
            ),
        ):
            result = execute(ctx)

        assert result["provider"] == "gcp"
        assert result["count"] == 1
        assert result["secrets"][0]["name"] == "db-password"
        assert result["secrets"][0]["value"] == "super-secret"
        assert result["secrets"][0]["content_type"] == "text/plain"

    def test_falls_back_to_access_denied_marker_when_payload_fetch_fails(self):
        ctx = _ctx()
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.return_value = [MagicMock(project_id="proj-1")]

        mock_secretmanager = MagicMock()
        mock_client = mock_secretmanager.SecretManagerServiceClient.return_value

        secret = MagicMock()
        secret.name = "projects/proj-1/secrets/app-token"
        secret.annotations = {}
        mock_client.list_secrets.return_value = [secret]
        mock_client.access_secret_version.side_effect = RuntimeError("denied")

        with (
            patch(
                "quantum_mechanic.techniques.collection.get_secrets.resourcemanager_v3",
                mock_rm,
            ),
            patch(
                "quantum_mechanic.techniques.collection.get_secrets.secretmanager",
                mock_secretmanager,
            ),
        ):
            result = execute(ctx)

        assert result["count"] == 1
        assert result["secrets"][0]["value"] == "[ACCESS DENIED]"


class TestGetSecretsAWS:
    def test_retrieves_aws_secret_string(self):
        ctx = _ctx(provider="aws", secret_name="prod/db-password")
        client = MagicMock()
        client.list_secrets.return_value = {
            "SecretList": [
                {
                    "Name": "prod/db-password",
                    "ARN": (
                        "arn:aws:secretsmanager:us-east-1:111122223333:"
                        "secret:prod/db-password"
                    ),
                }
            ]
        }
        client.get_secret_value.return_value = {"SecretString": "super-secret"}

        ctx.session.get_available_regions.return_value = ["us-east-1"]
        ctx.session.client.return_value = client

        result = execute(ctx)

        assert result["provider"] == "aws"
        assert result["count"] == 1
        assert result["secrets"][0]["value"] == "super-secret"
        assert result["secrets"][0]["content_type"] == "text/plain"

    def test_marks_access_denied_when_secret_read_fails(self):
        ctx = _ctx(provider="aws")
        client = MagicMock()
        client.list_secrets.return_value = {
            "SecretList": [
                {
                    "Name": "prod/api-token",
                    "ARN": (
                        "arn:aws:secretsmanager:us-east-1:111122223333:"
                        "secret:prod/api-token"
                    ),
                }
            ]
        }
        client.get_secret_value.side_effect = RuntimeError("denied")

        ctx.session.get_available_regions.return_value = ["us-east-1"]
        ctx.session.client.return_value = client

        result = execute(ctx)

        assert result["count"] == 1
        assert result["secrets"][0]["value"] == "[ACCESS DENIED]"
