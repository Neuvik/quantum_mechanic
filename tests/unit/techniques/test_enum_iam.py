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

    def test_gcp_expired_credential_caught_before_grpc_call(self, mock_ctx):
        """OUTCOME: an expired static token is caught by the pre-flight
        refresh check, before the gRPC client is ever constructed.

        This matters because resourcemanager_v3.ProjectsClient uses gRPC
        transport, and gRPC's AuthMetadataPlugin re-wraps ANY exception
        raised during credential refresh as a generic
        ServiceUnavailable("...Getting metadata from plugin failed...") —
        which is not a subclass of any auth-specific exception type and
        would otherwise be silently swallowed by the generic except-and-
        continue path, reproducing a milder version of issue #1."""
        mock_ctx.provider_name = "gcp"
        mock_ctx.whoami.return_value.principal_id = "test@example.com"
        mock_ctx.whoami.return_value.principal_type = "user"
        mock_ctx.whoami.return_value.account_id = "proj-1"
        mock_ctx.session.expired = True
        mock_ctx.session.refresh.side_effect = ValueError(
            "This GCP token was captured statically via `import gcp --default` "
            "and has expired. Please run `import gcp --default` again."
        )

        with patch("quantum_mechanic.techniques.discovery.enum_iam.resourcemanager_v3") as mock_rm:
            res = execute(mock_ctx)

            assert res["status"] == "error"
            assert "has expired" in res["error"]
            # The pre-flight check must short-circuit BEFORE the gRPC
            # client is ever constructed or called.
            mock_rm.ProjectsClient.assert_not_called()

    def test_gcp_fresh_credential_skips_refresh(self, mock_ctx):
        """OUTCOME: a non-expired credential is never refreshed — no
        needless network call on the common/happy path."""
        mock_ctx.provider_name = "gcp"
        mock_ctx.whoami.return_value.principal_id = "test@example.com"
        mock_ctx.whoami.return_value.principal_type = "user"
        mock_ctx.whoami.return_value.account_id = "proj-1"
        mock_ctx.session.expired = False

        with patch("quantum_mechanic.techniques.discovery.enum_iam.resourcemanager_v3") as mock_rm:
            mock_client = MagicMock()
            mock_rm.ProjectsClient.return_value = mock_client
            mock_client.search_projects.return_value = []

            execute(mock_ctx)

            mock_ctx.session.refresh.assert_not_called()

    def test_gcp_auth_failure_reports_error_not_empty_success(self, mock_ctx):
        """OUTCOME: an auth-layer failure while searching projects is
        reported as status=error, never as a "successful" empty result
        (issue #1 — silent auth failures must not look like a clean scan)."""
        from google.auth import exceptions as gauth_exceptions

        mock_ctx.provider_name = "gcp"
        mock_ctx.whoami.return_value.principal_id = "test@example.com"
        mock_ctx.whoami.return_value.principal_type = "user"
        mock_ctx.whoami.return_value.account_id = "proj-1"

        with patch("quantum_mechanic.techniques.discovery.enum_iam.resourcemanager_v3") as mock_rm:
            mock_client = MagicMock()
            mock_rm.ProjectsClient.return_value = mock_client
            mock_client.search_projects.side_effect = gauth_exceptions.RefreshError(
                "can't compare offset-naive and offset-aware datetimes"
            )

            res = execute(mock_ctx)

            assert res["status"] == "error"
            assert "authentication failed" in res["error"]
            assert res["project_roles"] == []

    def test_gcp_auth_failure_on_all_projects_reports_error(self, mock_ctx):
        """OUTCOME: if every project's IAM-policy fetch fails on auth
        (not permission), the technique reports error, not empty success."""
        from google.auth import exceptions as gauth_exceptions

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
            mock_client.get_iam_policy.side_effect = gauth_exceptions.RefreshError("expired")

            res = execute(mock_ctx)

            assert res["status"] == "error"
            assert "authentication failed" in res["error"]
            assert res["project_roles"] == []

    def test_gcp_permission_denied_on_one_project_still_succeeds(self, mock_ctx):
        """OUTCOME: a per-project permission denial (expected during real
        enumeration) is NOT treated as an auth failure — it's distinct from
        credentials being broken, and shouldn't abort the whole scan."""
        from google.api_core import exceptions as gapi_exceptions

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
            mock_client.get_iam_policy.side_effect = gapi_exceptions.PermissionDenied(
                "caller lacks resourcemanager.projects.getIamPolicy"
            )

            res = execute(mock_ctx)

            assert res["status"] == "success"
            assert res["project_roles"] == []

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

            # Setup recursive compartments
            mock_comp = MagicMock()
            mock_comp.id = "ocid1.compartment..child"
            mock_client.list_compartments.return_value.data = [mock_comp]

            # Setup policies for both tenancy and child compartment
            mock_policy1 = MagicMock()
            mock_policy1.id = "pol1"
            mock_policy1.name = "TenancyPolicy"
            mock_policy1.statements = ["Allow group Admins to manage all-resources in tenancy"]

            mock_policy2 = MagicMock()
            mock_policy2.id = "pol2"
            mock_policy2.name = "ChildPolicy"
            mock_policy2.statements = ["Allow group Admins to read instances in compartment"]

            def mock_list_policies(compartment_id):
                resp = MagicMock()
                if compartment_id == "ocid1.tenancy..456":
                    resp.data = [mock_policy1]
                else:
                    resp.data = [mock_policy2]
                return resp

            mock_client.list_policies.side_effect = mock_list_policies

            res = execute(mock_ctx)

            assert res["status"] == "success"
            assert len(res["groups"]) == 1
            assert res["groups"][0]["name"] == "Admins"
            assert len(res["policies"]) == 2
            
            policy_names = [p["name"] for p in res["policies"]]
            assert "TenancyPolicy" in policy_names
            assert "ChildPolicy" in policy_names
