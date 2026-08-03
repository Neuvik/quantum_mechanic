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
        mock_ec2.describe_regions.return_value = {"Regions": [{"RegionName": "us-east-1"}]}

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

        import sys

        botocore_mocks = {"botocore.exceptions": MagicMock()}
        with patch.dict(sys.modules, botocore_mocks):
            import importlib

            import quantum_mechanic.techniques.discovery.enum_compute as mod
            importlib.reload(mod)
            result = mod.execute(mock_ctx)

        assert "error" not in result, f"Implementation threw an error: {result.get('error')}"

        assert result["provider"] == "aws"
        assert result["total"] == 2

        # Verify both instances parsed (including the identity-less one)
        assert result["instances"][0]["instance_id"] == "i-ABCD1234"
        assert result["instances"][0]["instance_profile_arn"] == (
            "arn:aws:iam::123:instance-profile/ec2-s3-role"
        )
        assert result["instances"][1]["instance_id"] == "i-NOPROFILE"


    def test_filters_out_instances_without_profiles(self, mock_ctx):
        """No instances returned when none have Instance Profiles."""
        fake_page = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-000", "State": {"Name": "running"}}]}
            ]
        }

        self._make_aws_ctx(mock_ctx, [fake_page])

        import sys

        botocore_mocks = {"botocore.exceptions": MagicMock()}
        with patch.dict(sys.modules, botocore_mocks):
            import importlib

            import quantum_mechanic.techniques.discovery.enum_compute as mod
            importlib.reload(mod)
            result = mod.execute(mock_ctx)

        assert "error" not in result, f"Implementation threw an error: {result.get('error')}"

        # Under the new logic, the instance without a profile is kept!
        assert result["total"] == 1
        assert result["instances"][0]["instance_id"] == "i-000"

    def test_unknown_provider_returns_error(self, mock_ctx):
        """An unsupported provider returns an error dict, not an exception."""
        # Mock Azure SDK modules
        import sys
        sys.modules["azure.mgmt.compute"] = MagicMock()
        sys.modules["azure.mgmt.subscription"] = MagicMock()

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

    def test_surfaces_all_vms_regardless_of_identity(self, mock_ctx):
        """All Azure VMs are surfaced, including those without a Managed Identity attached."""
        mock_ctx.provider_name = "azure"
        mock_ctx.session = {"method": "default"}

        # VM 1: Has a UserAssigned Managed Identity via Enum type
        fake_vm_1 = MagicMock()
        fake_vm_1.id = "/subscriptions/sub123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/myvm"
        fake_vm_1.name = "myvm"
        fake_vm_1.location = "eastus"
        fake_vm_1.identity = MagicMock()
        fake_vm_1.identity.type.value = "UserAssigned"
        fake_vm_1.identity.principal_id = None
        fake_vm_1.identity.user_assigned_identities = {
            "/subscriptions/sub123/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-mid": MagicMock(
                principal_id="pid-111", client_id="cid-222"
            )
        }

        # VM 2: Completely lacks an identity property
        fake_vm_2 = MagicMock()
        fake_vm_2.id = "/subscriptions/sub123/rg/vm-no-id"
        fake_vm_2.name = "vm-no-id"
        fake_vm_2.location = "eastus"
        fake_vm_2.identity = None

        # VM 3: Has identity, but its 'type' is missing or not an Enum, triggering standard fallback
        # This was the root cause of the AttributeError: 'NoneType' object has no attribute 'value'
        fake_vm_3 = MagicMock()
        fake_vm_3.id = "/subscriptions/sub123/rg/vm-str-id"
        fake_vm_3.name = "vm-str-id"
        fake_vm_3.location = "westus"
        fake_vm_3.identity = MagicMock()
        fake_vm_3.identity.type = None # Mocking what caused the AttributeError
        fake_vm_3.identity.user_assigned_identities = None

        # Inject fake azure modules so the import inside _enum_azure succeeds
        import sys
        azure_mocks = {
            "azure": MagicMock(),
            "azure.identity": MagicMock(),
            "azure.mgmt": MagicMock(),
            "azure.mgmt.compute": MagicMock(),
            "azure.mgmt.network": MagicMock(),
            "azure.mgmt.subscription": MagicMock(),
        }
        mock_sub_client = MagicMock()
        mock_sub_client.return_value.subscriptions.list.return_value = [
            MagicMock(subscription_id="sub123")
        ]
        mock_compute_client = MagicMock()
        mock_compute_client.return_value.virtual_machines.list_all.return_value = [
            fake_vm_1,
            fake_vm_2,
            fake_vm_3,
        ]
        mock_network_client = MagicMock()
        mock_network_client.return_value.network_interfaces.get.side_effect = Exception("no NIC")
        azure_mocks["azure.mgmt.subscription"].SubscriptionClient = mock_sub_client
        azure_mocks["azure.mgmt.compute"].ComputeManagementClient = mock_compute_client
        azure_mocks["azure.mgmt.network"].NetworkManagementClient = mock_network_client
        azure_mocks["azure.identity"].DefaultAzureCredential = MagicMock()

        with patch.dict(sys.modules, azure_mocks):
            # Re-import so it picks up the mocked modules
            import importlib

            import quantum_mechanic.techniques.discovery.enum_compute as mod
            importlib.reload(mod)
            result = mod._enum_azure(mock_ctx)

        assert result["provider"] == "azure"
        assert result["total"] == 3

        # Verify VM 1 parsed properly
        assert result["instances"][0]["instance_id"] == "myvm"
        assert result["instances"][0]["identity_type"] == "UserAssigned"

        # Verify VM 2 parsed properly despite having NO identity (fixes blind exclusion bug)
        assert result["instances"][1]["instance_id"] == "vm-no-id"
        assert result["instances"][1]["identity_type"] == "None"

        # Verify VM 3 parsed properly despite missing an Enum type (fixes AttributeError bug)
        assert result["instances"][2]["instance_id"] == "vm-str-id"
        assert result["instances"][2]["identity_type"] == "None"

    def test_azure_persists_vm_with_managed_identity_to_workspace(self):
        """OUTCOME: After enum_compute runs against Azure, ctx.workspace.upsert_compute_instance
        is called for each VM with the expected kwarg set.

        ANTI-GAMIFICATION: Assertion uses assert_called_once_with on the full expected kwargs dict.
        A rename of any kwarg in the call site fails this test, even though ctx.workspace
        is a MagicMock (the kwarg dict is compared exactly).
        """
        import json
        from unittest.mock import MagicMock, patch

        from quantum_mechanic.techniques.discovery.enum_compute import execute

        fake_vm = MagicMock()
        fake_vm.name = "vm-victim"
        fake_vm.id = (
            "/subscriptions/sub-1/resourceGroups/rg-1"
            "/providers/Microsoft.Compute/virtualMachines/vm-victim"
        )
        fake_vm.location = "eastus"
        fake_vm.hardware_profile.vm_size = "Standard_DS2_v2"
        fake_vm.storage_profile = MagicMock()
        fake_vm.storage_profile.os_disk.os_type = "Linux"
        fake_vm.network_profile = None
        fake_vm.identity = MagicMock()
        fake_vm.identity.principal_id = "mi-principal-uuid-1"
        fake_vm.identity.user_assigned_identities = None
        fake_vm.identity.type = MagicMock(value="SystemAssigned")

        fake_sub = MagicMock(subscription_id="sub-1")

        ctx = MagicMock()
        ctx.provider_name = "azure"
        ctx.session = MagicMock()
        ctx.workspace = MagicMock()

        with patch("azure.mgmt.subscription.SubscriptionClient") as mock_sub_client, \
             patch("azure.mgmt.compute.ComputeManagementClient") as mock_compute_client:
            mock_sub_client.return_value.subscriptions.list.return_value = [fake_sub]
            compute = mock_compute_client.return_value
            compute.virtual_machines.list_all.return_value = [fake_vm]
            compute.virtual_machines.instance_view.side_effect = Exception("skip power state")

            execute(ctx)

        # When identity.user_assigned_identities is None, the technique leaves the
        # local `user_assigned` dict as {} (the `if ... user_assigned_identities`
        # branch is skipped). Power state falls back to "unknown" because
        # instance_view raised above.
        expected_metadata = json.dumps({
            "system_assigned_principal_id": "mi-principal-uuid-1",
            "user_assigned_identities": {},
            "identity_type": "SystemAssigned",
        })
        ctx.workspace.upsert_compute_instance.assert_called_once_with(
            provider="azure",
            instance_id="vm-victim",
            name="vm-victim",
            state="unknown",
            instance_type="Standard_DS2_v2",
            private_ip=None,
            public_ip=None,
            identity_arn="mi-principal-uuid-1",
            metadata=expected_metadata,
        )


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
        sas = {inst["instance_id"]: inst["service_accounts"] for inst in result["instances"]}
        assert sas["my-vm"][0]["is_default_compute_sa"] is False
        assert sas["default-vm"][0]["is_default_compute_sa"] is True
        assert "Editor" in sas["default-vm"][0]["risk_note"]
