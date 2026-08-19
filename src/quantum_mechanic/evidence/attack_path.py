# ================================================================
# MODULE: quantum_mechanic.evidence.attack_path
# ----------------------------------------------------------------
# PURPOSE:   Renders the ATTACK_PATH.md narrative document from
#            the workspace SQLite database.
#
# DESIGN:    The attack path is auto-generated every time a
#            technique runs. It reads from the workspace database
#            and renders a structured narrative:
#
#              - Credential chain (how we got each identity)
#              - Technique run timeline (what ran, what it found)
#              - Critical findings summary
#
#            This is the "money doc" — what you hand to the client
#            and what the blue team uses for detection.
#
#            The file is always at: <workspace_dir>/ATTACK_PATH.md
# ================================================================

from __future__ import annotations

import logging
import textwrap
from datetime import UTC, datetime
from pathlib import Path

from quantum_mechanic.core.workspace import Workspace

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity.lower(), "⚪")


def _build_credential_chain(workspace: Workspace) -> str:
    """Render a credential provenance tree as markdown."""
    creds = workspace.list_credentials()
    if not creds:
        return "_No credentials loaded._\n"

    # Build adjacency map: derived_from_id → list of children
    children: dict[int | None, list] = {}
    for c in creds:
        parent = c.derived_from_id
        children.setdefault(parent, []).append(c)

    lines: list[str] = []

    def render(cred_id: int | None, depth: int) -> None:
        for c in children.get(cred_id, []):
            indent = "    " * depth
            prefix = "└─ " if depth > 0 else ""
            obtained = f" ← {c.obtained_via}" if c.obtained_via else ""
            name = c.friendly_name or c.credential_type
            status_marker = (
                " ⚠ expiring"
                if c.status == "expiring"
                else (" ✗ expired" if c.status == "expired" else "")
            )
            lines.append(
                f"{indent}{prefix}**#{c.id}** {c.provider.upper()} `{name}`{obtained}{status_marker}"
            )
            render(c.id, depth + 1)

    render(None, 0)
    return "\n".join(lines) + "\n"


def _build_technique_timeline(workspace: Workspace) -> str:
    """Render an ordered timeline of technique runs from evidence table."""
    evidence_rows = workspace.list_evidence()
    if not evidence_rows:
        return "_No techniques have been run yet._\n"

    rows: list[str] = []
    rows.append("| # | Timestamp | Technique | Provider | Principal |")
    rows.append("|---|-----------|-----------|----------|-----------|")

    for i, row in enumerate(evidence_rows, 1):
        ts = str(row.get("timestamp", ""))[:16]
        tech = row.get("technique_id", "unknown")
        row.get("credential_id", "?")

        # Attempt to get provider from output_json
        import json

        provider = "?"
        principal = "?"
        try:
            data = json.loads(row.get("output_json", "{}"))
            provider = data.get("provider", "?")
            principal = data.get("principal") or data.get("friendly_name") or "?"
        except Exception as e:
            logger.debug("Could not parse output_json for evidence row %s: %s", row.get("id"), e)

        link = f"[{tech}](techniques/{tech.replace('/', '/')}.md)"
        rows.append(f"| {i} | `{ts}` | {link} | {provider.upper()} | `{principal}` |")

    return "\n".join(rows) + "\n"


def _build_findings_summary(workspace: Workspace) -> str:
    """Render a findings summary table from the findings table."""
    findings = workspace.list_findings()
    if not findings:
        return "_No findings recorded yet._\n"

    rows: list[str] = []
    rows.append("| ID | Severity | Title | Provider | Technique |")
    rows.append("|----|----------|-------|----------|-----------|")

    for f in sorted(
        findings,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            x.get("severity", "info").lower(), 99
        ),
    ):
        fid = f.get("id", "?")
        severity = f.get("severity", "info")
        emoji = _severity_emoji(severity)
        title = f.get("title", "Untitled")
        provider = f.get("provider", "?").upper()
        tech = f.get("technique_id", "?")
        slug = title.lower().replace(" ", "_")[:40]
        link = f"[{title}](findings/F{fid:03d}_{slug}.md)"
        rows.append(f"| F{fid:03d} | {emoji} {severity.upper()} | {link} | {provider} | `{tech}` |")

    return "\n".join(rows) + "\n"


def _build_provider_summary(workspace: Workspace) -> str:
    """Short summary of which providers are in scope."""
    creds = workspace.list_credentials()
    providers = sorted({c.provider for c in creds})
    if not providers:
        return "_No providers in scope._\n"
    return ", ".join(p.upper() for p in providers) + "\n"


def render(workspace: Workspace, workspace_dir: Path) -> Path:
    """Render ATTACK_PATH.md from the live workspace database.

    This is called automatically after every technique run.
    The file is overwritten each time — it always reflects the
    current state of the engagement.

    Args:
        workspace: The active Workspace instance
        workspace_dir: Root directory for the workspace files

    Returns:
        Path to the rendered ATTACK_PATH.md file
    """
    workspace_dir.mkdir(parents=True, exist_ok=True)
    out_path = workspace_dir / "ATTACK_PATH.md"

    cred_chain = _build_credential_chain(workspace)
    technique_timeline = _build_technique_timeline(workspace)
    findings_summary = _build_findings_summary(workspace)
    providers_in_scope = _build_provider_summary(workspace)

    content = textwrap.dedent(f"""\
        # Attack Path — {workspace.name}

        **Updated:** {_now()}
        **Providers:** {providers_in_scope}
        ---

        ## Credential Chain

        How each identity was obtained:

        {cred_chain}
        ---

        ## Technique Timeline

        Every technique run in order:

        {technique_timeline}
        ---

        ## Findings

        {findings_summary}
        ---

        *Generated by Quantum Mechanic. Open individual technique notes in `techniques/`
        or finding cards in `findings/` for full details.*
    """)

    out_path.write_text(content, encoding="utf-8")
    return out_path
