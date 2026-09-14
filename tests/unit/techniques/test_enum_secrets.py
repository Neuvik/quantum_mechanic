from unittest.mock import MagicMock, patch

from quantum_mechanic.techniques.discovery.enum_secrets import execute


def _ctx(
    provider: str = "gcp",
    *,
    account_id: str = "proj-default",
    target: str | None = None,
) -> MagicMock:
    ctx = MagicMock()
    ctx.provider_name = provider
    ctx.session = MagicMock()
    ctx.get_param.side_effect = lambda name, default=None: target if name == "target" else default
    ctx.whoami.return_value = MagicMock(account_id=account_id)
    return ctx


class TestEnumSecretsGCP:
    def test_unknown_provider_returns_error(self):
        result = execute(_ctx(provider="azure"))
        assert "error" in result
        assert "secrets" in result

    def test_import_guard_returns_error(self):
        with (
            patch("quantum_mechanic.techniques.discovery.enum_secrets.secretmanager", None),
            patch("quantum_mechanic.techniques.discovery.enum_secrets.resourcemanager_v3", None),
        ):
            result = execute(_ctx())

        assert "error" in result
        assert "google-cloud-secret-manager" in result["error"]

    def test_enumerates_secret_manager_inventory(self):
        ctx = _ctx()
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.return_value = [MagicMock(project_id="proj-1")]

        mock_secretmanager = MagicMock()
        mock_client = mock_secretmanager.SecretManagerServiceClient.return_value

        secret = MagicMock()
        secret.name = "projects/proj-1/secrets/app-prod-password"
        replication = MagicMock()
        replication.automatic = object()
        replication.user_managed = None
        secret.replication = replication
        mock_client.list_secrets.return_value = [secret]

        with (
            patch(
                "quantum_mechanic.techniques.discovery.enum_secrets.resourcemanager_v3",
                mock_rm,
            ),
            patch(
                "quantum_mechanic.techniques.discovery.enum_secrets.secretmanager",
                mock_secretmanager,
            ),
        ):
            result = execute(ctx)

        assert result["provider"] == "gcp"
        assert result["total"] == 1
        assert result["secrets"][0]["name"] == "app-prod-password"
        assert result["secrets"][0]["backend"] == "Secret Manager (automatic)"

    def test_target_filter_only_returns_matching_secret(self):
        ctx = _ctx(target="keep-me")
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.return_value = [MagicMock(project_id="proj-1")]

        mock_secretmanager = MagicMock()
        mock_client = mock_secretmanager.SecretManagerServiceClient.return_value

        keep = MagicMock()
        keep.name = "projects/proj-1/secrets/keep-me"
        keep.replication = MagicMock(automatic=object(), user_managed=None)

        drop = MagicMock()
        drop.name = "projects/proj-1/secrets/drop-me"
        drop.replication = MagicMock(automatic=object(), user_managed=None)

        mock_client.list_secrets.return_value = [keep, drop]

        with (
            patch(
                "quantum_mechanic.techniques.discovery.enum_secrets.resourcemanager_v3",
                mock_rm,
            ),
            patch(
                "quantum_mechanic.techniques.discovery.enum_secrets.secretmanager",
                mock_secretmanager,
            ),
        ):
            result = execute(ctx)

        assert result["total"] == 1
        assert result["secrets"][0]["name"] == "keep-me"
        assert result["secrets"][0]["scope"] == "proj-1"


class TestEnumSecretsAWS:
    def test_aws_enumerates_secrets_manager_inventory(self):
        ctx = _ctx(provider="aws")
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

        ctx.session.get_available_regions.return_value = ["us-east-1"]
        ctx.session.client.return_value = client

        result = execute(ctx)

        assert result["provider"] == "aws"
        assert result["total"] == 1
        assert result["secrets"][0]["scope"] == "us-east-1"
        assert result["secrets"][0]["backend"] == "Secrets Manager"
