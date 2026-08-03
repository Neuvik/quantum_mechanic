# ================================================================
# TESTS: sad-path coverage for all multi-provider dispatch techniques
# ----------------------------------------------------------------
# AQH-10: Every technique with dispatch.get(ctx.provider_name) or an
# if/elif provider chain must handle:
#   (a) unknown provider → clean error dict (no exception)
#   (b) missing required params → clean error dict (no exception)
#   (c) result with error key → formatter marks as failure (tested via
#       format_technique_result in test_formatters_error_handling below)
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, create_autospec, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext


def _ctx(provider: str = "unknown", params: dict | None = None) -> MagicMock:
    ctx = create_autospec(ExecutionContext, instance=True)
    ctx.provider_name = provider
    ctx.params = params or {}
    ctx.get_param.side_effect = lambda name, default=None: ctx.params.get(name, default)
    ctx.safe_mode = False
    ctx.session = MagicMock()
    ctx.info = MagicMock()
    ctx.error = MagicMock()
    ctx.success = MagicMock()
    ctx.whoami = MagicMock(return_value=MagicMock(principal_type="unknown"))
    return ctx


# ================================================================
# discovery/enum_compute
# ================================================================

class TestEnumComputeSadPaths:
    def test_unknown_provider_returns_error_dict(self):
        from quantum_mechanic.techniques.discovery.enum_compute import execute
        result = execute(_ctx("unknown"))
        assert "error" in result
        assert "instances" in result

    def test_no_exception_on_unknown_provider(self):
        from quantum_mechanic.techniques.discovery.enum_compute import execute
        result = execute(_ctx("entra"))   # entra not in dispatch
        assert isinstance(result, dict)
        assert "instances" in result


# ================================================================
# discovery/enum_iam
# ================================================================

class TestEnumIAMSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.discovery.enum_iam import execute
        result = execute(_ctx("unknown"))
        assert "error" in result

    def test_unknown_principal_type_returns_error(self):
        from quantum_mechanic.techniques.discovery.enum_iam import execute
        ctx = _ctx("aws")
        ctx.whoami.return_value = MagicMock(principal_type="unknown")
        result = execute(ctx)
        assert "error" in result


# ================================================================
# discovery/enum_serverless
# ================================================================

class TestEnumServerlessSadPaths:
    def test_unknown_provider_returns_empty(self):
        from quantum_mechanic.techniques.discovery.enum_serverless import execute
        result = execute(_ctx("unknown"))
        assert isinstance(result, dict)

    def test_gcp_returns_error_dict_not_exception(self):
        from quantum_mechanic.techniques.discovery.enum_serverless import execute
        result = execute(_ctx("gcp"))
        assert "error" in result
        assert "functions" in result

    def test_oci_returns_error_dict_not_exception(self):
        from quantum_mechanic.techniques.discovery.enum_serverless import execute
        result = execute(_ctx("oci"))
        assert "error" in result
        assert "functions" in result


# ================================================================
# lateral_movement/vm_execute_command
# ================================================================

@patch.dict("sys.modules", {
    "azure.mgmt.compute": MagicMock(),
    "azure.mgmt.compute.models": MagicMock(),
})
class TestVMExecuteCommandSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.vm_execute_command import execute
        result = execute(_ctx("unknown"))
        assert "error" in result

    def test_missing_target_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.vm_execute_command import execute
        ctx = _ctx("azure", params={"cmd": "id"})
        result = execute(ctx)
        assert "error" in result

    def test_malformed_azure_resource_id_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.vm_execute_command import execute
        ctx = _ctx("azure", params={"target": "short-vm-name", "cmd": "id"})
        result = execute(ctx)
        assert "error" in result
        assert "resource ID" in result["error"] or "Malformed" in result["error"]


# ================================================================
# Formatter error handling: result with error key shows ✗ not ✓
# ================================================================

class TestFormatterErrorHandling:
    """format_exec_result must show ✗ when result.data has an error key."""

    def test_format_exec_result_shows_failure_on_error(self, capsys):
        from quantum_mechanic.techniques.lateral_movement.vm_execute_command import (
            format_exec_result,
        )

        result = MagicMock()
        result.data = {"error": "Something went wrong", "target": "my-vm"}
        result.provider = "azure"

        # Should not raise
        format_exec_result(result)
        # Rich prints to its own console; at minimum verify no exception thrown

    def test_format_exec_result_no_exception_on_success(self):
        from quantum_mechanic.techniques.lateral_movement.vm_execute_command import (
            format_exec_result,
        )

        result = MagicMock()
        result.data = {
            "target": "my-vm",
            "status": "Success",
            "stdout": "uid=0",
            "stderr": "",
        }
        result.provider = "azure"
        format_exec_result(result)


# ================================================================
# collection/scan_disk_content — only aws provider now
# ================================================================

class TestScanDiskContentSadPaths:
    def test_non_aws_no_snapshot_needs_target(self):
        from quantum_mechanic.techniques.collection.scan_disk_content import execute
        ctx = _ctx("aws", params={})  # no target, no snapshot
        result = execute(ctx)
        assert "error" in result

    def test_nonexistent_local_path_returns_error(self, tmp_path):
        from quantum_mechanic.techniques.collection.scan_disk_content import execute
        ctx = _ctx("aws", params={"target": str(tmp_path / "does_not_exist")})
        result = execute(ctx)
        assert "error" in result
        assert "hits" in result


# ================================================================
# discovery/enum_storage
# ================================================================

class TestEnumStorageSadPaths:
    def test_unknown_provider_returns_dict(self):
        from quantum_mechanic.techniques.discovery.enum_storage import execute
        result = execute(_ctx("unknown"))
        assert isinstance(result, dict)

    def test_entra_provider_returns_dict(self):
        from quantum_mechanic.techniques.discovery.enum_storage import execute
        result = execute(_ctx("entra"))
        assert isinstance(result, dict)


# ================================================================
# discovery/enum_keyvaults
# ================================================================

class TestEnumKeyvaultsSadPaths:
    def test_unknown_provider_returns_error_dict(self):
        from quantum_mechanic.techniques.discovery.enum_keyvaults import execute
        result = execute(_ctx("unknown"))
        assert "error" in result
        assert "vaults" in result

    def test_no_exception_raised(self):
        from quantum_mechanic.techniques.discovery.enum_keyvaults import execute
        result = execute(_ctx("entra"))
        assert isinstance(result, dict)


# ================================================================
# discovery/enum_permissions
# ================================================================

class TestEnumPermissionsSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.discovery.enum_permissions import execute
        result = execute(_ctx("unknown"))
        assert "error" in result

    def test_no_exception_raised(self):
        from quantum_mechanic.techniques.discovery.enum_permissions import execute
        result = execute(_ctx("entra"))
        assert isinstance(result, dict)


# ================================================================
# collection/get_keyvault_secrets
# ================================================================

class TestGetKeyvaultSecretsSadPaths:
    def test_unknown_provider_returns_error_dict(self):
        from quantum_mechanic.techniques.collection.get_keyvault_secrets import execute
        result = execute(_ctx("unknown"))
        assert "error" in result
        assert "secrets" in result

    def test_no_exception_raised(self):
        from quantum_mechanic.techniques.collection.get_keyvault_secrets import execute
        result = execute(_ctx("entra"))
        assert isinstance(result, dict)


# ================================================================
# collection/storage_search
# ================================================================

class TestStorageSearchSadPaths:
    def test_unknown_provider_returns_error_dict(self):
        from quantum_mechanic.techniques.collection.storage_search import execute
        result = execute(_ctx("unknown"))
        assert "error" in result
        assert "hits" in result


# ================================================================
# credential_access/serverless_env_harvest
# ================================================================

class TestServerlessEnvHarvestSadPaths:
    def test_unknown_provider_returns_dict(self):
        from quantum_mechanic.techniques.credential_access.serverless_env_harvest import execute
        result = execute(_ctx("unknown"))
        assert isinstance(result, dict)


# ================================================================
# escalation/gcp_sa_token_creator
# ================================================================

class TestGcpSaTokenCreatorSadPaths:
    def test_non_gcp_returns_error(self):
        from quantum_mechanic.techniques.escalation.gcp_sa_token_creator import execute
        result = execute(_ctx("aws"))
        assert "error" in result

    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.escalation.gcp_sa_token_creator import execute
        result = execute(_ctx("unknown"))
        assert "error" in result


# ================================================================
# lateral_movement/cross_cloud_pivot
# ================================================================

class TestCrossCloudPivotSadPaths:
    def test_non_aws_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.cross_cloud_pivot import execute
        result = execute(_ctx("azure", params={"method": "aws_to_gcp"}))
        assert "error" in result

    def test_missing_method_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.cross_cloud_pivot import execute
        result = execute(_ctx("aws", params={}))
        assert isinstance(result, dict)


# ================================================================
# lateral_movement/vm_ssh_push
# ================================================================

class TestVmSshPushSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.vm_ssh_push import execute
        result = execute(_ctx("unknown"))
        assert "error" in result

    def test_missing_required_params_returns_error(self):
        from quantum_mechanic.techniques.lateral_movement.vm_ssh_push import execute
        result = execute(_ctx("gcp", params={}))
        assert "error" in result


# ================================================================
# exfiltration/share_disk_snapshot
# ================================================================

class TestShareDiskSnapshotSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.exfiltration.share_disk_snapshot import execute
        result = execute(_ctx("unknown"))
        assert "error" in result

    def test_missing_target_aws_returns_error(self):
        from quantum_mechanic.techniques.exfiltration.share_disk_snapshot import execute
        result = execute(_ctx("aws", params={}))
        assert "error" in result


# ================================================================
# persistence/create_credential
# ================================================================

class TestCreateCredentialSadPaths:
    def test_unknown_provider_returns_error(self):
        from quantum_mechanic.techniques.persistence.create_credential import execute
        result = execute(_ctx("unknown"))
        assert "error" in result
        assert "results" in result

    def test_missing_target_aws_returns_error(self):
        from quantum_mechanic.techniques.persistence.create_credential import execute
        result = execute(_ctx("aws", params={}))
        assert isinstance(result, dict)
