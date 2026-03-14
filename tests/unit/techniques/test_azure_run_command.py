# ================================================================
# TESTS: lateral_movement/azure_run_command
# ================================================================
#
# Strategy: azure-mgmt-compute is not installed in the test
# environment, but azure_run_command.py imports it at MODULE LEVEL
# with a try/except guard (setting _AZURE_AVAILABLE = False when
# absent). Tests patch the module-level names:
#   quantum_mechanic.techniques.lateral_movement.azure_run_command.ComputeManagementClient
#   quantum_mechanic.techniques.lateral_movement.azure_run_command.RunCommandInput
#   quantum_mechanic.techniques.lateral_movement.azure_run_command._AZURE_AVAILABLE
# ================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from quantum_mechanic.core.context import ExecutionContext

_MODULE = "quantum_mechanic.techniques.lateral_movement.azure_run_command"


def _make_ctx(*, safe_mode: bool = False, params: dict | None = None) -> MagicMock:
    """Build a minimal mock ExecutionContext for azure_run_command tests."""
    # TD-2: use spec= so attribute typos fail loudly at test time.
    ctx = MagicMock(spec=ExecutionContext)
    ctx.safe_mode = safe_mode
    ctx.params = params or {}
    ctx.provider_name = "azure"
    ctx.session = MagicMock()
    return ctx


VM_ID = (
    "/subscriptions/sub-123/resourceGroups/test-rg"
    "/providers/Microsoft.Compute/virtualMachines/test-vm"
)


class TestAzureRunCommandMissingParams:
    def test_missing_vm_id_returns_error(self):
        """Should return error dict when vm_id is not provided."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", MagicMock()):
            ctx = _make_ctx(params={})
            result = execute(ctx)

        assert "error" in result
        assert "vm_id" in result["error"]

    def test_empty_vm_id_returns_error(self):
        """Empty vm_id string should return error."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", MagicMock()):
            ctx = _make_ctx(params={"vm_id": "  "})
            result = execute(ctx)

        assert "error" in result

    def test_malformed_vm_id_returns_error(self):
        """Non-resource-ID string should return parse error."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", MagicMock()):
            ctx = _make_ctx(params={"vm_id": "not-a-valid-resource-id"})
            result = execute(ctx)

        assert "error" in result


class TestAzureRunCommandSafeMode:
    def test_safe_mode_does_not_call_api(self):
        """In safe_mode, should return a preview dict without calling Azure."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        mock_compute_cls = MagicMock()
        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", mock_compute_cls):
            ctx = _make_ctx(safe_mode=True, params={"vm_id": VM_ID, "command": "id"})
            result = execute(ctx)

        assert result["safe_mode"] is True
        assert result["would_execute"] is True
        assert result["stdout"] == ""
        mock_compute_cls.assert_not_called()


class TestAzureRunCommandSuccess:
    def test_linux_command_returns_stdout(self):
        """Successful Linux RunCommand should return stdout in result."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        mock_result_value = [
            MagicMock(code="ComponentStatus/StdOut/succeeded", message="uid=0(root)"),
            MagicMock(code="ComponentStatus/StdErr/succeeded", message=""),
        ]
        mock_poller = MagicMock()
        mock_poller.result.return_value = MagicMock(value=mock_result_value)
        mock_compute_instance = MagicMock()
        mock_compute_instance.virtual_machines.begin_run_command.return_value = mock_poller
        mock_compute_cls = MagicMock(return_value=mock_compute_instance)

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", mock_compute_cls), \
             patch(f"{_MODULE}.RunCommandInput", MagicMock(return_value=MagicMock())):
            ctx = _make_ctx(params={"vm_id": VM_ID, "command": "id"})
            result = execute(ctx)

        assert result["success"] is True
        assert "uid=0(root)" in result["stdout"]
        assert result["vm_name"] == "test-vm"
        assert result["subscription_id"] == "sub-123"
        assert result["resource_group"] == "test-rg"

    def test_correct_command_id_for_linux(self):
        """Should use RunShellScript for bash shell."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        mock_poller = MagicMock()
        mock_poller.result.return_value = MagicMock(value=[])
        mock_compute_instance = MagicMock()
        mock_compute_instance.virtual_machines.begin_run_command.return_value = mock_poller
        mock_compute_cls = MagicMock(return_value=mock_compute_instance)

        captured_id = {}

        def _mock_rci(**kwargs):
            captured_id["command_id"] = kwargs.get("command_id", "")
            return MagicMock()

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", mock_compute_cls), \
             patch(f"{_MODULE}.RunCommandInput", side_effect=_mock_rci):
            ctx = _make_ctx(params={"vm_id": VM_ID, "command": "id", "shell": "bash"})
            execute(ctx)

        assert captured_id.get("command_id") == "RunShellScript"

    def test_correct_command_id_for_powershell(self):
        """Should use RunPowerShellScript when shell=powershell."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        mock_poller = MagicMock()
        mock_poller.result.return_value = MagicMock(value=[])
        mock_compute_instance = MagicMock()
        mock_compute_instance.virtual_machines.begin_run_command.return_value = mock_poller
        mock_compute_cls = MagicMock(return_value=mock_compute_instance)

        captured_id = {}

        def _mock_rci(**kwargs):
            captured_id["command_id"] = kwargs.get("command_id", "")
            return MagicMock()

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", mock_compute_cls), \
             patch(f"{_MODULE}.RunCommandInput", side_effect=_mock_rci):
            ctx = _make_ctx(params={"vm_id": VM_ID, "command": "whoami", "shell": "powershell"})
            execute(ctx)

        assert captured_id.get("command_id") == "RunPowerShellScript"

    def test_api_exception_returns_error_dict(self):
        """API failures should return an error dict, not raise."""
        from quantum_mechanic.techniques.lateral_movement.azure_run_command import execute

        mock_compute_cls = MagicMock(side_effect=Exception("Azure 403 Forbidden"))

        with patch(f"{_MODULE}._AZURE_AVAILABLE", True), \
             patch(f"{_MODULE}.ComputeManagementClient", mock_compute_cls), \
             patch(f"{_MODULE}.RunCommandInput", MagicMock()):
            ctx = _make_ctx(params={"vm_id": VM_ID})
            result = execute(ctx)

        assert "error" in result
        assert "403" in result["error"]
