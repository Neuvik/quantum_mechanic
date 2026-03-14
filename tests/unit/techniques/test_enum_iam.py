# ================================================================
# TESTS: quantum_mechanic.techniques.discovery.enum_iam
# ================================================================

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.providers.base import WhoAmIResult
from quantum_mechanic.techniques.discovery.enum_iam import execute


@pytest.fixture
def mock_ctx():
    """Build a mocked ExecutionContext."""
    ctx = MagicMock(spec=ExecutionContext)
    ctx.provider_name = "aws"
    ctx.session = MagicMock()

    # Mock whoami response
    ctx.whoami.return_value = WhoAmIResult(
        provider="aws",
        principal_id="arn:aws:iam::123:user/testuser",
        principal_type="user",
        friendly_name="testuser",
        account_id="123",
        extra={},
        raw_response={},
    )

    return ctx


class TestEnumIAM:
    def test_unsupported_provider(self):
        """Technique skips non-implemented providers smoothly."""
        ctx = MagicMock(spec=ExecutionContext)
        ctx.provider_name = "fakecloud"

        res = execute(ctx)
        assert "not yet implemented" in res["error"]
        assert res["policies"] == []

    def test_unknown_principal(self, mock_ctx):
        """Fails gracefully if the principal type isn't known."""
        mock_ctx.whoami.return_value.principal_type = "unknown"
        res = execute(mock_ctx)

        assert "Could not determine principal" in res["error"]

    def test_unsupported_principal(self, mock_ctx):
        """Fails gracefully if the principal isn't an IAM user or role."""
        mock_ctx.whoami.return_value.principal_type = "root"
        res = execute(mock_ctx)

        assert "not supported for principal type: root" in res["error"]

    def test_user_enumeration_success(self, mock_ctx):
        """Successfully lists and fetches policies for a user."""
        mock_iam = MagicMock()
        mock_ctx.session.client.return_value = mock_iam

        # Setup paginators
        def mock_get_paginator(operation):
            paginator = MagicMock()
            if operation == "list_attached_user_policies":
                paginator.paginate.return_value = [
                    {"AttachedPolicies": [{"PolicyName": "Admin", "PolicyArn": "arn:admin"}]}
                ]
            elif operation == "list_user_policies":
                paginator.paginate.return_value = [{"PolicyNames": ["InlinePol"]}]
            return paginator

        mock_iam.get_paginator.side_effect = mock_get_paginator

        # Setup specific gets
        mock_iam.get_user_policy.return_value = {"PolicyDocument": {"Statement": []}}
        mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": ["admin-rules"]}}
        }

        res = execute(mock_ctx)

        assert res["status"] == "success"
        assert res["principal"] == "testuser"
        assert len(res["attached_policies"]) == 1
        assert len(res["inline_policies"]) == 1
        assert len(res["policy_documents"]) == 2  # 1 inline, 1 managed

        docs = {d["PolicyName"]: d for d in res["policy_documents"]}
        assert docs["InlinePol"]["Source"] == "inline"
        assert docs["Admin"]["Source"] == "managed"

    def test_role_enumeration_success(self, mock_ctx):
        """Successfully lists and fetches policies for an assumed role."""
        mock_ctx.whoami.return_value.principal_type = "assumed_role"
        mock_ctx.whoami.return_value.friendly_name = "testrole"

        mock_iam = MagicMock()
        mock_ctx.session.client.return_value = mock_iam

        def mock_get_paginator(operation):
            paginator = MagicMock()
            if operation == "list_attached_role_policies":
                paginator.paginate.return_value = [
                    {"AttachedPolicies": [{"PolicyName": "Read", "PolicyArn": "arn:read"}]}
                ]
            elif operation == "list_role_policies":
                paginator.paginate.return_value = [{"PolicyNames": ["RoleInline"]}]
            return paginator

        mock_iam.get_paginator.side_effect = mock_get_paginator
        mock_iam.get_role_policy.return_value = {"PolicyDocument": {}}
        mock_iam.get_policy.return_value = {}  # simulates missing version id

        res = execute(mock_ctx)

        assert res["status"] == "success"
        assert len(res["attached_policies"]) == 1
        assert len(res["policy_documents"]) == 1  # only inline fetched, since get_policy failed

    def test_permission_denied_graceful_exit(self, mock_ctx):
        """API AccessDenied exceptions are caught without terminating."""
        mock_iam = MagicMock()
        mock_ctx.session.client.return_value = mock_iam
        mock_iam.get_paginator.side_effect = Exception("Access Denied")

        res = execute(mock_ctx)

        assert "IAM enumeration failed" in res["error"]
        assert res["attached_policies"] == []
        assert res["policy_documents"] == []

    def test_azure_enumeration_success(self, mock_ctx):
        """Successfully lists Azure RBAC assignments."""
        mock_ctx.provider_name = "azure"
        mock_ctx.whoami.return_value.extra = {"subscriptions": [{"id": "sub1"}]}

        with patch(
            "quantum_mechanic.techniques.discovery.enum_iam.AuthorizationManagementClient"
        ) as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            mock_assignment = MagicMock()
            mock_assignment.id = "assign1"
            mock_assignment.scope = "/subscriptions/sub1"
            mock_assignment.role_definition_id = "role_def_1"

            mock_client.role_assignments.list_for_subscription.return_value = [mock_assignment]

            mock_role_def = MagicMock()
            mock_role_def.role_name = "Contributor"
            mock_client.role_definitions.get_by_id.return_value = mock_role_def

            res = execute(mock_ctx)

            assert res["status"] == "success"
            assert len(res["role_assignments"]) == 1
            assert res["role_assignments"][0]["roleName"] == "Contributor"

    def test_azure_no_subscriptions(self, mock_ctx):
        mock_ctx.provider_name = "azure"
        mock_ctx.whoami.return_value.extra = {}

        res = execute(mock_ctx)
        assert "status" in res
        assert res["status"] == "error"
        assert "No accessible subscriptions" in res["error"]

    def test_gcp_enumeration_success(self, mock_ctx):
        """Successfully lists GCP IAM roles."""
        mock_ctx.provider_name = "gcp"
        mock_ctx.whoami.return_value.principal_id = "test@example.com"
        mock_ctx.whoami.return_value.principal_type = "user"
        mock_ctx.whoami.return_value.account_id = "proj-1"

        with patch("quantum_mechanic.techniques.discovery.enum_iam.resourcemanager_v3") as mock_rm:
            mock_client = MagicMock()
            mock_rm.ProjectsClient.return_value = mock_client

            mock_project = MagicMock()
            mock_project.project_id = "proj-1"
            mock_client.search_projects.return_value = [mock_project]

            mock_policy = MagicMock()
            mock_binding = MagicMock()
            mock_binding.role = "roles/viewer"
            mock_binding.members = ["user:test@example.com"]
            mock_binding.condition = None
            mock_policy.bindings = [mock_binding]

            mock_client.get_iam_policy.return_value = mock_policy

            res = execute(mock_ctx)

            assert res["status"] == "success"
            assert len(res["project_roles"]) == 1
            assert res["project_roles"][0]["role"] == "roles/viewer"

    def test_gcp_no_projects(self, mock_ctx):
        mock_ctx.provider_name = "gcp"
        mock_ctx.whoami.return_value.account_id = None

        with patch("quantum_mechanic.techniques.discovery.enum_iam.resourcemanager_v3") as mock_rm:
            mock_client = MagicMock()
            mock_rm.ProjectsClient.return_value = mock_client
            mock_client.search_projects.return_value = []

            res = execute(mock_ctx)
            assert res["status"] == "error"
            assert "No projects found" in res["error"]

    def test_oci_instance_principal(self, mock_ctx):
        mock_ctx.provider_name = "oci"
        mock_ctx.whoami.return_value.principal_type = "instance_principal"
        mock_ctx.whoami.return_value.friendly_name = "instance"
        mock_ctx.session = {"config": {}, "signer": MagicMock()}

        with patch("oci.identity.IdentityClient"):
            res = execute(mock_ctx)

        assert res["error"] == "Instance Principal enumeration not fully supported yet."

    def test_oci_enumeration_success(self, mock_ctx):
        mock_ctx.provider_name = "oci"
        mock_ctx.whoami.return_value.principal_id = "ocid1.user..123"
        mock_ctx.whoami.return_value.principal_type = "user"
        mock_ctx.whoami.return_value.tenant_id = "ocid1.tenancy..456"
        mock_ctx.whoami.return_value.friendly_name = "testuser"

        mock_ctx.session = {"config": {"region": "us-ashburn-1"}}

        with patch("oci.identity.IdentityClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client

            # Setup memberships
            mock_membership = MagicMock()
            mock_membership.group_id = "group1"
            mock_client.list_user_group_memberships.return_value.data = [mock_membership]

            # Setup group details
            mock_group = MagicMock()
            mock_group.id = "group1"
            mock_group.name = "Admins"
            mock_client.get_group.return_value.data = mock_group

            # Setup policies
            mock_policy = MagicMock()
            mock_policy.id = "pol1"
            mock_policy.name = "AllAccess"
            mock_policy.statements = ["Allow group Admins to manage all-resources in tenancy"]
            mock_client.list_policies.return_value.data = [mock_policy]

            res = execute(mock_ctx)

            assert res["status"] == "success"
            assert len(res["groups"]) == 1
            assert res["groups"][0]["name"] == "Admins"
            assert len(res["tenancy_policies"]) == 1
            assert res["tenancy_policies"][0]["name"] == "AllAccess"
