# ================================================================
# TESTS: tests/unit/techniques/test_enum_compute.py
# ----------------------------------------------------------------
# PURPOSE:  Unit tests for discovery/enum_compute.
#           All external SDK calls are mocked — no real credentials
#           or cloud access is required.
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext


@pytest.fixture
def mock_ctx():
    """Build a minimal ExecutionContext stub."""
    ctx = MagicMock(spec=ExecutionContext)
    return ctx


# ================================================================
# AWS tests
# ================================================================

class TestEnumComputeAWS:
    """Tests for the AWS _enum_aws path."""

    def _make_aws_ctx(self, mock_ctx, fake_pages):
        """Set up ctx.session as a mock boto3.Session with a configured EC2 client."""
        mock_ec2 = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = fake_pages
        mock_ec2.get_paginator.return_value = mock_paginator

        mock_session = MagicMock()
        mock_session.client.return_value = mock_ec2
        mock_ctx.session = mock_session
        mock_ctx.provider_name = "aws"
        return mock_ec2

    def test_returns_instances_with_profiles(self, mock_ctx):
        """Only EC2 instances with an attached Instance Profile are surfaced."""
        fake_page = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            # This instance HAS a profile — should appear.
                            "InstanceId": "i-ABCD1234",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "KeyName": "my-key",
                            "SubnetId": "subnet-aaa",
                            "SecurityGroups": [{"GroupId": "sg-111"}],
                            "PrivateIpAddress": "10.0.0.5",
                            "PublicIpAddress": "1.2.3.4",
                            "ImageId": "ami-1234",
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123:instance-profile/ec2-s3-role",
                                "Id": "AIPATEST",
                            },
                        },
                        {
                            # This instance has NO profile — should be excluded.
                            "InstanceId": "i-NOPROFILE",
                            "InstanceType": "t3.nano",
                            "State": {"Name": "running"},
                            "SubnetId": "subnet-bbb",
                            "SecurityGroups": [],
                        },
                    ]
                }
            ]
        }

        self._make_aws_ctx(mock_ctx, [fake_page])

        from quantum_mechanic.techniques.discovery.enum_compute import execute
        result = execute(mock_ctx)

        assert result["provider"] == "aws"
        assert result["total"] == 1
        assert result["instances"][0]["instance_id"] == "i-ABCD1234"
        assert result["instances"][0]["instance_profile_arn"] == (
            "arn:aws:iam::123:instance-profile/ec2-s3-role"
        )

    def test_filters_out_instances_without_profiles(self, mock_ctx):
        """No instances returned when none have Instance Profiles."""
        fake_page = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-000", "State": {"Name": "running"}}]}
            ]
        }

        self._make_aws_ctx(mock_ctx, [fake_page])

        from quantum_mechanic.techniques.discovery.enum_compute import execute
        result = execute(mock_ctx)

        assert result["total"] == 0
        assert result["instances"] == []

    def test_unknown_provider_returns_error(self, mock_ctx):
        """An unsupported provider returns an error dict, not an exception."""
        mock_ctx.provider_name = "unknowncloud"
        mock_ctx.session = {}

        from quantum_mechanic.techniques.discovery.enum_compute import execute
        result = execute(mock_ctx)

        assert "error" in result
        assert "not implemented" in result["error"]


# ================================================================
# Azure tests
# ================================================================

class TestEnumComputeAzure:
    """Tests for the Azure _enum_azure path."""

    def test_returns_vms_with_managed_identity(self, mock_ctx):
        """Only Azure VMs with a Managed Identity attached are surfaced."""
        mock_ctx.provider_name = "azure"
        mock_ctx.session = {"method": "default"}

        fake_vm = MagicMock()
        fake_vm.id = "/subscriptions/sub123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/myvm"
        fake_vm.name = "myvm"
        fake_vm.location = "eastus"
        fake_vm.identity = MagicMock()
        fake_vm.identity.type.value = "UserAssigned"
        fake_vm.identity.principal_id = None
        fake_vm.identity.user_assigned_identities = {
            "/subscriptions/sub123/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-mid": MagicMock(
                principal_id="pid-111", client_id="cid-222"
            )
        }

        fake_vm_no_id = MagicMock()
        fake_vm_no_id.identity = None  # No identity — should be excluded.

        # Inject fake azure modules so the import inside _enum_azure succeeds
        import sys
        azure_mocks = {
            "azure": MagicMock(),
            "azure.identity": MagicMock(),
            "azure.mgmt": MagicMock(),
            "azure.mgmt.compute": MagicMock(),
            "azure.mgmt.resource": MagicMock(),
        }
        mock_sub_client = MagicMock()
        mock_sub_client.return_value.subscriptions.list.return_value = [
            MagicMock(subscription_id="sub123")
        ]
        mock_compute_client = MagicMock()
        mock_compute_client.return_value.virtual_machines.list_all.return_value = [
            fake_vm,
            fake_vm_no_id,
        ]
        azure_mocks["azure.mgmt.resource"].SubscriptionClient = mock_sub_client
        azure_mocks["azure.mgmt.compute"].ComputeManagementClient = mock_compute_client
        azure_mocks["azure.identity"].DefaultAzureCredential = MagicMock()

        with patch.dict(sys.modules, azure_mocks):
            # Re-import so it picks up the mocked modules
            import importlib
            import quantum_mechanic.techniques.discovery.enum_compute as mod
            importlib.reload(mod)
            result = mod._enum_azure(mock_ctx)

        assert result["provider"] == "azure"
        assert result["total"] == 1
        assert result["instances"][0]["name"] == "myvm"


# ================================================================
# GCP tests
# ================================================================

class TestEnumComputeGCP:
    """Tests for the GCP _enum_gcp path."""

    def test_returns_instances_with_non_default_service_accounts(self, mock_ctx):
        """Only instances with non-default service accounts are surfaced."""
        mock_ctx.provider_name = "gcp"
        mock_ctx.session = {"method": "default"}

        fake_result = {
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {
                            "id": "123",
                            "name": "my-vm",
                            "zone": "https://zones/us-central1-a",
                            "status": "RUNNING",
                            "machineType": "https://machineTypes/e2-micro",
                            "serviceAccounts": [
                                {"email": "my-sa@my-project.iam.gserviceaccount.com"}
                            ],
                        },
                        {
                            # Default SA — should be excluded.
                            "id": "456",
                            "name": "default-vm",
                            "zone": "https://zones/us-central1-a",
                            "status": "RUNNING",
                            "machineType": "https://machineTypes/e2-micro",
                            "serviceAccounts": [
                                {"email": "123456789-compute@developer.gserviceaccount.com"}
                            ],
                        },
                    ]
                }
            }
        }

        import sys
        mock_google = MagicMock()
        mock_google.auth.default.return_value = (MagicMock(), "my-project")
        mock_compute_svc = MagicMock()
        mock_compute_svc.instances.return_value.aggregatedList.return_value.execute.return_value = fake_result
        mock_google_api_client = MagicMock()
        mock_google_api_client.discovery.build.return_value = mock_compute_svc

        gcp_mocks = {
            "google": mock_google,
            "google.auth": mock_google.auth,
            "googleapiclient": mock_google_api_client,
            "googleapiclient.discovery": mock_google_api_client.discovery,
        }
        with patch.dict(sys.modules, gcp_mocks):
            import importlib
            import quantum_mechanic.techniques.discovery.enum_compute as mod
            importlib.reload(mod)
            result = mod._enum_gcp(mock_ctx)

        assert result["provider"] == "gcp"
        # Both instances are now returned — default SA is annotated, not excluded.
        assert result["total"] == 2
        sas = {inst["name"]: inst["service_accounts"] for inst in result["instances"]}
        assert sas["my-vm"][0]["is_default_compute_sa"] is False
        assert sas["default-vm"][0]["is_default_compute_sa"] is True
        assert "Editor" in sas["default-vm"][0]["risk_note"]
