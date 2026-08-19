# ================================================================
# MODULE: quantum_mechanic.evidence.writer
# ----------------------------------------------------------------
# PURPOSE:   Writes rich markdown notes for each technique run
#            into the workspace directory tree.
#
# DESIGN:    Output structure per workspace:
#            ~/.quantum_mechanic/workspaces/<name>/
#              techniques/<tactic>/<technique_name>.md
#              findings/CRIT-001_<slug>.md
#
#            The markdown notes are designed to be opened in
#            Obsidian, VS Code, or any markdown editor. Raw API
#            responses are in collapsible <details> blocks.
#
#            Every write is idempotent — re-running a technique
#            overwrites the note with the latest result.
# ================================================================

from __future__ import annotations

import json
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _detection_block(technique_id: str) -> str:
    """Return the blue team detection block for a technique."""
    _DETECTIONS: dict[str, str] = {
        "discovery/whoami": textwrap.dedent("""\
            | Provider | Event |
            |----------|-------|
            | AWS      | CloudTrail: `sts:GetCallerIdentity` |
            | Azure    | Azure Monitor: `Microsoft.Resources/subscriptions/read` |
            | GCP      | Cloud Audit Logs: `resourcemanager.projects.list` |
            | OCI      | OCI Audit: `identity.user.get` |
        """),
        "discovery/enum_iam": textwrap.dedent("""\
            | Provider | Event |
            |----------|-------|
            | AWS      | CloudTrail: `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` |
            | Azure    | Azure Monitor: `Microsoft.Authorization/roleAssignments/read` |
            | GCP      | Cloud Audit Logs: `cloudresourcemanager.projects.getIamPolicy` |
            | OCI      | OCI Audit: `identity.group.list`, `identity.policy.list` |
        """),
        "discovery/enum_compute": textwrap.dedent("""\
            | Provider | Event |
            |----------|-------|
            | AWS      | CloudTrail: `ec2:DescribeInstances`, `ec2:DescribeIamInstanceProfileAssociations` |
            | Azure    | Azure Monitor: `Microsoft.Compute/virtualMachines/read` |
            | GCP      | Cloud Audit Logs: `compute.instances.list` (Data Access) |
            | OCI      | OCI Audit: `instance.list` |
        """),
    }
    return _DETECTIONS.get(
        technique_id, "_Detection signatures not yet documented for this technique._\n"
    )


def write_technique_note(
    *,
    workspace_dir: Path,
    technique_id: str,
    tactic: str,
    provider: str,
    principal: str,
    summary: str,
    risk_flags: list[str],
    raw_data: Any,
    duration_ms: int,
    api_calls: int,
) -> Path:
    """Write a rich markdown note for a technique run.

    Args:
        workspace_dir: Root of the workspace directory.
        technique_id: e.g. "discovery/enum_iam"
        tactic: ATT&CK tactic name
        provider: Cloud provider ("aws", "azure", "gcp", "oci")
        principal: Friendly name of the current identity
        summary: One-line summary from the summarizer
        risk_flags: List of risk flag strings
        raw_data: The raw dict returned by execute(ctx)
        duration_ms: Execution time
        api_calls: Number of API calls made

    Returns:
        Path to the written markdown file.
    """
    # ------------------------------------------------------------------
    # Build output path: techniques/<tactic>/<name>.md
    # ------------------------------------------------------------------
    name = technique_id.split("/")[-1]
    out_dir = workspace_dir / "techniques" / tactic
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{name}.md"

    # ------------------------------------------------------------------
    # Format the raw data section.
    # ------------------------------------------------------------------
    try:
        raw_json = json.dumps(raw_data, indent=2, default=str)
    except Exception:
        raw_json = str(raw_data)

    # ------------------------------------------------------------------
    # Build flags section.
    # ------------------------------------------------------------------
    flags_section = ""
    if risk_flags:
        flag_lines = "\n".join(f"- `{f}`" for f in risk_flags)
        flags_section = f"\n## ⚠ Risk Flags\n{flag_lines}\n"

    # ------------------------------------------------------------------
    # Write the note.
    # ------------------------------------------------------------------
    content = textwrap.dedent(f"""\
        # {technique_id.replace("/", " / ")}

        **Provider:** {provider.upper()}  **Principal:** `{principal}`
        **Run:** {_now()}  **Duration:** {duration_ms}ms  **API Calls:** {api_calls}

        ## Summary

        {summary}
        {flags_section}
        ## Detection Signatures (Blue Team)

        {_detection_block(technique_id)}
        ## Raw Evidence

        <details>
        <summary>Full API Response (click to expand)</summary>

        ```json
        {raw_json}
        ```

        </details>
    """)

    out_path.write_text(content, encoding="utf-8")
    return out_path


def write_finding_note(
    *,
    workspace_dir: Path,
    finding_id: str,
    title: str,
    severity: str,
    technique_id: str,
    provider: str,
    description: str,
    evidence: dict,
    detection_signatures: dict | None = None,
    remediation: str = "",
) -> Path:
    """Write a finding card to findings/<SEVERITY-ID_slug>.md.

    Args:
        workspace_dir: Root of the workspace directory.
        finding_id: e.g. "CRIT-001"
        title: Short title of the finding
        severity: "critical" | "high" | "medium" | "low" | "info"
        technique_id: Which technique discovered this
        provider: Cloud provider
        description: What was found and why it matters
        evidence: Structured evidence dict
        detection_signatures: Blue team detection info
        remediation: How to fix it

    Returns:
        Path to the written markdown file.
    """
    out_dir = workspace_dir / "findings"
    out_dir.mkdir(parents=True, exist_ok=True)

    slug = title.lower().replace(" ", "_").replace("/", "_")[:40]
    out_path = out_dir / f"{finding_id}_{slug}.md"

    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity.lower(), "⚪")

    evidence_json = json.dumps(evidence, indent=2, default=str)

    detection_section = ""
    if detection_signatures:
        rows = "\n".join(f"| {k} | `{v}` |" for k, v in detection_signatures.items())
        detection_section = (
            f"\n## Detection Signatures (Blue Team)\n\n| Provider | Event |\n|---|---|\n{rows}\n"
        )

    remediation_section = f"\n## Remediation\n\n{remediation}\n" if remediation else ""

    content = textwrap.dedent(f"""\
        # {severity_emoji} {finding_id}: {title}

        **Severity:** {severity.upper()}  **Provider:** {provider.upper()}
        **Technique:** `{technique_id}`  **Found:** {_now()}

        ## Description

        {description}
        {detection_section}{remediation_section}
        ## Evidence

        <details>
        <summary>Structured Evidence (click to expand)</summary>

        ```json
        {evidence_json}
        ```

        </details>
    """)

    out_path.write_text(content, encoding="utf-8")
    return out_path
