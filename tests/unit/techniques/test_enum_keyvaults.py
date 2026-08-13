from unittest.mock import MagicMock, patch

from quantum_mechanic.techniques.discovery.enum_keyvaults import execute


def _ctx(provider: str = "gcp", *, account_id: str = "proj-default") -> MagicMock:
    ctx = MagicMock()
    ctx.provider_name = provider
    ctx.session = MagicMock()
    ctx.get_param.return_value = None
    ctx.whoami.return_value = MagicMock(account_id=account_id)
    return ctx


class TestEnumKeyvaultsAWS:
    def test_aws_enumerates_kms_keys_and_aliases(self):
        ctx = _ctx(provider="aws")
        kms = MagicMock()
        kms.list_aliases.return_value = {
            "Aliases": [{"AliasName": "alias/app-prod", "TargetKeyId": "key-123"}],
            "Truncated": False,
        }
        kms.list_keys.return_value = {
            "Keys": [{"KeyId": "key-123"}],
            "Truncated": False,
        }
        kms.describe_key.return_value = {
            "KeyMetadata": {"Arn": "arn:aws:kms:us-east-1:111122223333:key/key-123"},
        }

        ctx.session.get_available_regions.return_value = ["us-east-1"]
        ctx.session.client.return_value = kms

        result = execute(ctx)

        assert result["provider"] == "aws"
        assert result["total"] == 1
        assert result["vaults"][0]["name"] == "alias/app-prod"
        assert result["vaults"][0]["location"] == "us-east-1"
        assert result["vaults"][0]["auth_model"] == "IAM + Key Policy"


class TestEnumKeyvaultsGCP:
    def test_gcp_import_guard_returns_error(self):
        with (
            patch("quantum_mechanic.techniques.discovery.enum_keyvaults.kms_v1", None),
            patch("quantum_mechanic.techniques.discovery.enum_keyvaults.resourcemanager_v3", None),
        ):
            result = execute(_ctx())

        assert "error" in result
        assert "google-cloud-kms" in result["error"]

    def test_gcp_enumerates_cloud_kms_key_rings(self):
        ctx = _ctx()
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.return_value = [MagicMock(project_id="proj-1")]

        mock_kms = MagicMock()
        mock_client = mock_kms.KeyManagementServiceClient.return_value
        key_ring = MagicMock()
        key_ring.name = "projects/proj-1/locations/us-central1/keyRings/ring-a"
        mock_client.list_key_rings.return_value = [key_ring]

        with (
            patch(
                "quantum_mechanic.techniques.discovery.enum_keyvaults.resourcemanager_v3",
                mock_rm,
            ),
            patch("quantum_mechanic.techniques.discovery.enum_keyvaults.kms_v1", mock_kms),
        ):
            result = execute(ctx)

        assert result["provider"] == "gcp"
        assert result["total"] == 1
        assert result["vaults"][0]["name"] == "ring-a"
        assert result["vaults"][0]["location"] == "us-central1"
        assert result["vaults"][0]["auth_model"] == "IAM"
        assert result["vaults"][0]["project_id"] == "proj-1"

    def test_gcp_falls_back_to_default_project(self):
        ctx = _ctx(account_id="fallback-proj")
        mock_rm = MagicMock()
        mock_projects = mock_rm.ProjectsClient.return_value
        mock_projects.search_projects.side_effect = RuntimeError("denied")

        mock_kms = MagicMock()
        mock_client = mock_kms.KeyManagementServiceClient.return_value
        mock_client.list_key_rings.return_value = []

        with (
            patch(
                "quantum_mechanic.techniques.discovery.enum_keyvaults.resourcemanager_v3",
                mock_rm,
            ),
            patch("quantum_mechanic.techniques.discovery.enum_keyvaults.kms_v1", mock_kms),
        ):
            result = execute(ctx)

        assert result["provider"] == "gcp"
        mock_client.list_key_rings.assert_called_once_with(
            request={"parent": "projects/fallback-proj/locations/-"}
        )
        ctx.warn.assert_called()
