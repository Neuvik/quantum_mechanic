# ================================================================
# TECHNIQUE: discovery/enum_storage_acls
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1069.003 — Permission Groups Discovery: Cloud Groups
#
# PURPOSE:
#   Identify storage buckets suffering from severe misconfigurations
#   resulting in  unintended public internet exposure or excessively broad
#   internal access. By resolving deeply attached Access Control Lists
#   (ACLs) and bucket policies,  an attacker maps out directly exploitable
#   vectors for mass data exfiltration and identifies buckets that can be
#   immediately downloaded via anonymous access.
#
# PROVIDERS: aws, azure, gcp, oci
#
#
# HOW IT WORKS (AWS):
#   Requires s3:ListAllMyBuckets and s3:GetBucketAcl. Executes
#   s3.list_buckets() and iterates over the entire estate invoking
#   s3.get_bucket_acl(Bucket=name). Inspects the payload for Grants
#   pointing to 'AllUsers' or 'AuthenticatedUsers'.
#
# DETECTION (AWS):
#   CloudTrail: GetBucketAcl. This technique represents active vulnerability
#   scanning  vs simple enumeration. Alert on high-volume sweeps of
#   GetBucketAcl metrics.
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.Storage/storageAccounts/read. Evaluates the
#   allow_blob_public_access property explicitly for True across all
#   Storage Accounts.
#
# DETECTION (AZURE):
#   Azure Monitor: Microsoft.Storage/storageAccounts/read. High volume
#   properties reads.
#
# HOW IT WORKS (GCP):
#   Requires storage.buckets.getIamPolicy. Actively targets all
#   available buckets  pulling the IAM policy to evaluate if
#   roles/storage.objectViewer is mapped  anonymously to allUsers.
#
# DETECTION (GCP):
#   Cloud Audit Logs: storage.buckets.getIamPolicy (Admin Activity). Bulk
#   policy resolution.
#
# HOW IT WORKS (OCI):
#   Requires BUCKET_READ. Resolves the public_access_type attribute
#   across all  identified Object Storage constructs mapping exposed
#   namespaces.
#
# DETECTION (OCI):
#   OCI Audit: ReadBucket looking for broad configuration mapping.
# REFERENCES:
#   - https://attack.mitre.org/techniques/T1069/003/
#   - https://hackingthe.cloud/aws/exploitation/s3_exposure/
#
# SAFE:      Yes
# ================================================================


from __future__ import annotations

from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'buckets'
LOOT_SCHEMA = [
    ('name',              'Bucket Name',   'bold cyan'),
    ('public',            'Public',        'red'),
    ('vulnerable_reason', 'Risk Reason',   'yellow'),
]


@technique(
    technique_id='discovery/enum_storage_acls',
    tactic='discovery',
    mitre_id='T1069.003',
    providers=['aws', 'azure', 'gcp', 'oci'],
    severity='medium',
    safe=True,
    description='Actively evaluate bucket policies and Access Control Lists for public exposure.',
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Actively evaluate bucket policies and Access Control Lists for public exposure.

    Generated from: enum_storage_acls.yaml
    See: docs/architecture/attack_maps/ for full attack chain.
    """
    if ctx.provider_name == 'aws':
        return _aws(ctx)
    if ctx.provider_name == 'azure':
        return _azure(ctx)
    if ctx.provider_name == 'gcp':
        return _gcp(ctx)
    if ctx.provider_name == 'oci':
        return _oci(ctx)

    return {}


# ---------------------------------------------------------------------------
# Per-provider implementations
# ---------------------------------------------------------------------------
def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires s3:ListAllMyBuckets and s3:GetBucketAcl. Executes
    s3.list_buckets() and iterates over the entire estate invoking
    s3.get_bucket_acl(Bucket=name). Inspects the payload for Grants
    pointing to 'AllUsers' or 'AuthenticatedUsers'.

    DETECTION:
    CloudTrail: GetBucketAcl. This technique represents active
    vulnerability scanning  vs simple enumeration. Alert on high-volume
    sweeps of GetBucketAcl metrics.

    TESTING INFRASTRUCTURE:
    Construct a public-facing S3 bucket explicitly granting ObjectRead
    to AllUsers via an ACL mapping. Grant attacker role
    s3:ListAllMyBuckets and s3:GetBucketAcl.
    """
    try:
        from botocore.exceptions import ClientError
        s3 = ctx.session.client("s3")
        buckets = []
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b.get("Name")
            is_public = False
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        is_public = True
            except ClientError:
                pass

            if is_public:
                import json as _json
                ctx.workspace.add_finding(
                    technique_id="discovery/enum_storage_acls",
                    tactic="discovery",
                    title=f"Publicly Exposed S3 Bucket ACL: {name}",
                    severity="high",
                    provider="aws",
                    description=f"Bucket '{name}' grants public access via ACL (AllUsers/AuthenticatedUsers).",
                    evidence=_json.dumps({"bucket": name, "public_acl": True}),
                    mitre_id="T1069.003",
                )
            buckets.append({"name": name, "public": is_public})

        return {
            "provider": "aws",
            "buckets": buckets,
            "vulnerable_count": sum(1 for b in buckets if b["public"]),
            "total": len(buckets),
        }
    except Exception as e:
        return {"provider": "aws", "error": str(e)}
def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires Microsoft.Storage/storageAccounts/read. Evaluates the
    allow_blob_public_access property explicitly for True across all
    Storage Accounts.

    DETECTION:
    Azure Monitor: Microsoft.Storage/storageAccounts/read. High volume
    properties reads.

    TESTING INFRASTRUCTURE:
    Create an Azure Storage Account with allow_blob_public_access set to
    True. Grant the attacker read rights.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires Microsoft.Storage/storageAccounts/read. Evaluates the  allow_blob_public_access property explicitly for True across all Storage Accounts.
    # -----------------------------------------------------------------
    # When you find an exploitable condition, report it:
    # ctx.finding(
    #     title=f"Over-privilege detected: enum storage acls (AZURE)",
    #     severity='medium',
    #     evidence={
    #         # add discovered resource fields here
    #     },
    #     recommendation="TODO: add remediation guidance",
    #     mitre_id='T1069.003',
    #     detection_log="Azure Monitor: Microsoft",
    # )
    # -----------------------------------------------------------------
    raise NotImplementedError(
        "Implement azure path — see docstring and attack map above."
    )
def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires storage.buckets.getIamPolicy. Actively targets all
    available buckets  pulling the IAM policy to evaluate if
    roles/storage.objectViewer is mapped  anonymously to allUsers.

    DETECTION:
    Cloud Audit Logs: storage.buckets.getIamPolicy (Admin Activity).
    Bulk policy resolution.

    TESTING INFRASTRUCTURE:
    Create a Cloud Storage Bucket granting storage.objectViewer to
    allUsers. Grant attacker Service Account read privileges.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires storage.buckets.getIamPolicy. Actively targets all available buckets  pulling the IAM policy to evaluate if roles/storage.objectViewer is mapped  anonymously to allUsers.
    # -----------------------------------------------------------------
    # When you find an exploitable condition, report it:
    # ctx.finding(
    #     title=f"Over-privilege detected: enum storage acls (GCP)",
    #     severity='medium',
    #     evidence={
    #         # add discovered resource fields here
    #     },
    #     recommendation="TODO: add remediation guidance",
    #     mitre_id='T1069.003',
    #     detection_log="Cloud Audit Logs: storage.buckets.getIamPolicy (Admin Activity). Bulk policy resolution.",
    # )
    # -----------------------------------------------------------------
    raise NotImplementedError(
        "Implement gcp path — see docstring and attack map above."
    )
def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires BUCKET_READ. Resolves the public_access_type attribute
    across all  identified Object Storage constructs mapping exposed
    namespaces.

    DETECTION:
    OCI Audit: ReadBucket looking for broad configuration mapping.

    TESTING INFRASTRUCTURE:
    Build an Object Storage bucket with public_access_type ObjectRead.
    Grant user read access.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires BUCKET_READ. Resolves the public_access_type attribute across all  identified Object Storage constructs mapping exposed namespaces.
    # -----------------------------------------------------------------
    # When you find an exploitable condition, report it:
    # ctx.finding(
    #     title=f"Over-privilege detected: enum storage acls (OCI)",
    #     severity='medium',
    #     evidence={
    #         # add discovered resource fields here
    #     },
    #     recommendation="TODO: add remediation guidance",
    #     mitre_id='T1069.003',
    #     detection_log="OCI Audit: ReadBucket looking for broad configuration mapping.",
    # )
    # -----------------------------------------------------------------
    raise NotImplementedError(
        "Implement oci path — see docstring and attack map above."
    )

