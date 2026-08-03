from unittest.mock import MagicMock, patch

from quantum_mechanic.core.runner import TechniqueResult
from quantum_mechanic.shell.formatters import format_technique_result
from quantum_mechanic.techniques.discovery.enum_iam import format_iam_result


@patch("quantum_mechanic.shell.formatters.console")
def test_format_technique_result_enum_iam_aws(mock_console):
    data = {
        "status": "success",
        "principal": "test-user",
        "principal_type": "user",
        "attached_policies": [{"PolicyName": "Admin", "PolicyArn": "arn:aws:iam::aws:policy/Admin"}],
        "inline_policies": [],
    }
    result = TechniqueResult(
        technique_id="discovery/enum_iam",
        provider="aws",
        status="success",
        data=data,
        api_calls=1,
        duration_ms=50,
        formatter_func=format_iam_result
    )

    format_technique_result(result)

    # We expect print to be called with a Panel or Table, not just a raw json dump.
    # We can check that print_json was NOT called, or that a Panel with "AWS IAM Enumeration" was printed.
    mock_console.print.assert_called()
    mock_console.print_json.assert_not_called()


@patch("quantum_mechanic.shell.formatters.console")
def test_format_technique_result_enum_iam_azure(mock_console):
    data = {
        "status": "success",
        "principal": "sp-123",
        "principal_type": "service_principal",
        "role_assignments": [{"roleName": "Contributor", "scope": "/subscriptions/sub-123"}],
    }
    result = TechniqueResult(
        technique_id="discovery/enum_iam",
        provider="azure",
        status="success",
        data=data,
        api_calls=1,
        duration_ms=50,
        formatter_func=format_iam_result
    )

    format_technique_result(result)
    mock_console.print.assert_called()
    mock_console.print_json.assert_not_called()


@patch("quantum_mechanic.shell.formatters.console")
def test_format_technique_result_enum_iam_gcp(mock_console):
    data = {
        "status": "success",
        "principal": "test@example.com",
        "principal_type": "user",
        "project_roles": [{"project": "proj-1", "role": "roles/viewer", "condition": None}],
    }
    result = TechniqueResult(
        technique_id="discovery/enum_iam",
        provider="gcp",
        status="success",
        data=data,
        api_calls=1,
        duration_ms=50,
        formatter_func=format_iam_result
    )

    format_technique_result(result)
    mock_console.print.assert_called()
    mock_console.print_json.assert_not_called()


@patch("quantum_mechanic.shell.formatters.console")
def test_format_technique_result_enum_iam_oci(mock_console):
    data = {
        "status": "success",
        "principal": "ocid1.user.123",
        "principal_type": "user",
        "groups": [{"name": "Admins"}],
        "tenancy_policies": [{"name": "TenantRoot", "statements": ["Allow group Admins to manage all"]}],
    }
    result = TechniqueResult(
        technique_id="discovery/enum_iam",
        provider="oci",
        status="success",
        data=data,
        api_calls=1,
        duration_ms=50,
        formatter_func=format_iam_result
    )

    format_technique_result(result)
    mock_console.print.assert_called()
    mock_console.print_json.assert_not_called()
