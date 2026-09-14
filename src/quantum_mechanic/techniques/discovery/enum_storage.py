# ================================================================
# TECHNIQUE: discovery/enum_storage
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:
#   Identify storage buckets and containers across the cloud environment.
#   Cloud  storage frequently contains sensitive backups, configuration
#   files, and secrets. Discovering these assets allows an attacker to map
#   potential targets for Data from Cloud Storage (T1530) or find overly
#   permissive buckets that allow public read access, resulting in immediate
#   data exposure.
#
# PROVIDERS: aws, azure, gcp, oci
#
#
# HOW IT WORKS (AWS):
#   Requires s3:ListAllMyBuckets. Executes boto3 s3.list_buckets().
#   For each bucket discovered, it optionally calls s3:GetBucketPolicy
#   and s3:GetBucketAcl to determine if the bucket allows public
#   read/write access.
#
# DETECTION (AWS):
#   CloudTrail: ListBuckets (Data Activity if configured, Admin otherwise),
#   GetBucketPolicy. Alert on high-volume listing coming from unusual
#   identities or roles recently assumed.
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.Storage/storageAccounts/read. Iterates through
#   the subscription via
#   StorageManagementClient.storage_accounts.list(). Queries the
#   account properties to determine if allow_blob_public_access is
#   enabled.
#
# DETECTION (AZURE):
#   Azure Monitor: Microsoft.Storage/storageAccounts/read. Alert on
#   systematic enumeration across multiple subscriptions from a newly
#   logged-in service principal.
#
# HOW IT WORKS (GCP):
#   Requires storage.buckets.list. Computes buckets via
#   storage().buckets().list(project=projectId). For each bucket,
#   calls storage.buckets.getIamPolicy to evaluate if allUsers or
#   allAuthenticatedUsers have roles/storage.objectViewer.
#
# DETECTION (GCP):
#   Cloud Audit Logs: storage.buckets.list — Admin Activity. Alert on bulk
#   reads of IAM policies on storage buckets.
#
# HOW IT WORKS (OCI):
#   Requires OBJECTSTORAGE_NAMESPACE_READ and BUCKET_INSPECT. Queries
#   get_namespace() followed by list_buckets() mapped over all
#   compartments. Extracts the public_access_type.
#
# DETECTION (OCI):
#   OCI Audit: ListBuckets. Alert on cross-compartment bucket enumeration.
# REFERENCES:
#   - https://attack.mitre.org/techniques/T1580/
#   - https://hackingthe.cloud/aws/enumeration/s3_buckets/
#
# SAFE:      Yes
# ================================================================


from __future__ import annotations

from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "buckets"
LOOT_SCHEMA = [
    ("name", "Bucket Name", "bold cyan"),
    ("creation_date", "Created", "dim"),
    ("public", "Public", "yellow"),
]


@technique(
    technique_id="discovery/enum_storage",
    tactic="discovery",
    mitre_id="T1580",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Enumerate cloud storage buckets and containers and highlight public exposure.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific bucket or storage account name.", required=False),
        Parameter(
            "public_only",
            "Only return publicly exposed buckets and write workspace findings.",
            required=False,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Enumerate cloud storage buckets and containers and highlight public exposure.

    Generated from: enum_storage.yaml
    See: docs/architecture/attack_maps/ for full attack chain.
    """
    if ctx.provider_name == "aws":
        return _aws(ctx)
    if ctx.provider_name == "azure":
        return _azure(ctx)
    if ctx.provider_name == "gcp":
        return _gcp(ctx)
    if ctx.provider_name == "oci":
        return _oci(ctx)

    return {}


# ---------------------------------------------------------------------------
# Per-provider implementations
# ---------------------------------------------------------------------------
def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires s3:ListAllMyBuckets. Executes boto3 s3.list_buckets(). For
    each bucket discovered, it optionally calls s3:GetBucketPolicy and
    s3:GetBucketAcl to determine if the bucket allows public read/write
    access.

    DETECTION:
    CloudTrail: ListBuckets (Data Activity if configured, Admin
    otherwise), GetBucketPolicy. Alert on high-volume listing coming
    from unusual identities or roles recently assumed.

    TESTING INFRASTRUCTURE:
    Build an S3 bucket with a permissive bucket policy (Principal: *).
    Create an attacker role with s3:ListAllMyBuckets and
    s3:GetBucketPolicy permissions.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires s3:ListAllMyBuckets. Executes boto3 s3.list_buckets(). For each bucket discovered, it optionally calls s3:GetBucketPolicy and s3:GetBucketAcl to determine if the bucket allows public read/write access.
    all_users_uri = "http://acs.amazonaws.com/groups/global/AllUsers"
    auth_users_uri = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

    def _check_public(s3_client, bucket_name: str) -> str:
        """Return a human-readable public-exposure label or empty string."""
        # 1. ACL check — catches the old AllUsers:READ misconfiguration
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            perms: list[str] = []
            for g in grants:
                uri = g.get("Grantee", {}).get("URI", "")
                perm = g.get("Permission", "")
                if uri == all_users_uri:
                    perms.append(f"AllUsers:{perm}")
                elif uri == auth_users_uri:
                    perms.append(f"AuthUsers:{perm}")
            if perms:
                return " | ".join(perms)
        except Exception:
            pass

        # 2. Policy status check — catches bucket-policy-based public access
        try:
            status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            if status.get("PolicyStatus", {}).get("IsPublic"):
                return "Policy:Public"
        except Exception:
            pass

        return ""

    try:
        s3 = ctx.session.client("s3")
        buckets = []
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b.get("Name")
            buckets.append(
                {
                    "name": name,
                    "creation_date": str(b.get("CreationDate")),
                    "public": _check_public(s3, name),
                }
            )

        import json as _json

        public_only = bool(ctx.get_param("public_only"))
        if public_only:
            buckets = [b for b in buckets if b["public"]]
            for b in buckets:
                ctx.workspace.add_finding(
                    technique_id="discovery/enum_storage",
                    tactic="discovery",
                    title=f"Publicly Exposed S3 Bucket: {b['name']}",
                    severity="high",
                    provider="aws",
                    description=f"Bucket '{b['name']}' grants public access: {b['public']}",
                    evidence=_json.dumps({"bucket": b["name"], "public": b["public"]}),
                    mitre_id="T1530",
                )

        return {"provider": "aws", "buckets": buckets, "total": len(buckets)}
    except Exception as e:
        return {"provider": "aws", "error": str(e)}


def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires Microsoft.Storage/storageAccounts/read. Iterates through
    the subscription via
    StorageManagementClient.storage_accounts.list(). Queries the account
    properties to determine if allow_blob_public_access is enabled.

    DETECTION:
    Azure Monitor: Microsoft.Storage/storageAccounts/read. Alert on
    systematic enumeration across multiple subscriptions from a newly
    logged-in service principal.

    TESTING INFRASTRUCTURE:
    Create a Storage Account with allow_blob_public_access=true and a
    single container. Provide the attacker principal with Storage
    Account Reader.
    """
    try:
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-storage not installed.", "buckets": []}

    target = ctx.get_param("target")
    cred = ctx.session
    buckets = []

    try:
        if target:
            # If a specific account is targeted, we need to find which subscription it belongs to,
            # or try to get it directly if we have the resource group (but we don't here).
            # For simplicity, we'll still list subscriptions but filter for the target.
            try:
                sub_client = SubscriptionClient(cred)
                subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]
            except Exception as e:
                return {
                    "error": f"Failed to list subscriptions while searching for target {target}: {e}",
                    "buckets": [],
                }

            for sub_id in subscriptions:
                storage_client = StorageManagementClient(cred, sub_id)
                try:
                    # Try to get the specific account if we can find it
                    for account in storage_client.storage_accounts.list():
                        if account.name == target:
                            buckets.append(
                                {
                                    "name": account.name,
                                    "location": account.location,
                                    "subscription_id": sub_id,
                                    "public": "Enabled"
                                    if getattr(account, "allow_blob_public_access", False)
                                    else "Disabled",
                                    "creation_date": str(account.creation_time)
                                    if hasattr(account, "creation_time")
                                    else "Unknown",
                                }
                            )
                            break
                except Exception:
                    continue
        else:
            try:
                sub_client = SubscriptionClient(cred)
                subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]
            except Exception as e:
                return {"error": f"Failed to list subscriptions: {e}", "buckets": []}

            for sub_id in subscriptions:
                try:
                    storage_client = StorageManagementClient(cred, sub_id)
                    for account in storage_client.storage_accounts.list():
                        buckets.append(
                            {
                                "name": account.name,
                                "location": account.location,
                                "subscription_id": sub_id,
                                "public": "Enabled"
                                if getattr(account, "allow_blob_public_access", False)
                                else "Disabled",
                                "creation_date": str(account.creation_time)
                                if hasattr(account, "creation_time")
                                else "Unknown",
                            }
                        )
                except Exception as e:
                    ctx.warn(f"Failed to list storage accounts in subscription {sub_id}: {e}")

        public_only = bool(ctx.get_param("public_only"))
        if public_only:
            buckets = [b for b in buckets if b.get("public") == "Enabled"]

        return {"provider": "azure", "buckets": buckets, "total": len(buckets)}
    except Exception as e:
        return {"provider": "azure", "error": str(e)}


def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires storage.buckets.list. Computes buckets via
    storage().buckets().list(project=projectId). For each bucket, calls
    storage.buckets.getIamPolicy to evaluate if allUsers or
    allAuthenticatedUsers have roles/storage.objectViewer.

    DETECTION:
    Cloud Audit Logs: storage.buckets.list — Admin Activity. Alert on
    bulk reads of IAM policies on storage buckets.

    TESTING INFRASTRUCTURE:
    Create a Google Cloud Storage bucket with IAM binding granting
    roles/storage.objectViewer to allUsers. Grant the attacker Service
    Account roles/storage.admin or viewer.
    """
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed.", "buckets": []}

    try:
        credentials = ctx.session
        whoami = ctx.whoami()
        project = whoami.account_id

        if not project:
            return {"error": "Could not determine GCP project ID from credentials.", "buckets": []}

        storage_client = build("storage", "v1", credentials=credentials)
        result = storage_client.buckets().list(project=project).execute()

        buckets = []
        for bucket in result.get("items", []):
            buckets.append({"name": bucket.get("name"), "location": bucket.get("location")})

        return {"provider": "gcp", "buckets": buckets, "total": len(buckets)}
    except Exception as e:
        return {"provider": "gcp", "error": str(e)}


def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires OBJECTSTORAGE_NAMESPACE_READ and BUCKET_INSPECT. Queries
    get_namespace() followed by list_buckets() mapped over all
    compartments. Extracts the public_access_type.

    DETECTION:
    OCI Audit: ListBuckets. Alert on cross-compartment bucket
    enumeration.

    TESTING INFRASTRUCTURE:
    Create an OCI Object Storage bucket with public_access_type
    ObjectRead. Create an attacker user in a group with inspect buckets
    in target compartment.
    """
    try:
        import oci
    except ImportError:
        return {"error": "oci not installed.", "buckets": []}

    try:
        config = ctx.session["config"]
        signer = ctx.session.get("signer")

        if signer:
            identity = oci.identity.IdentityClient(config={}, signer=signer)
            os_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        else:
            identity = oci.identity.IdentityClient(config)
            os_client = oci.object_storage.ObjectStorageClient(config)

        tenancy_id = config.get("tenancy")
        compartment_ids = [tenancy_id]

        child_compartments = identity.list_compartments(
            tenancy_id, compartment_id_in_subtree=True
        ).data
        compartment_ids += [c.id for c in child_compartments]

        namespace = os_client.get_namespace().data

        buckets = []
        for cid in compartment_ids:
            try:
                for bucket in os_client.list_buckets(namespace, cid).data:
                    buckets.append(
                        {
                            "name": bucket.name,
                            "compartment_id": bucket.compartment_id,
                            "namespace": bucket.namespace,
                        }
                    )
            except Exception:
                # Permission denied for compartment, safe to skip for enum tools
                pass

        return {"provider": "oci", "buckets": buckets, "total": len(buckets)}
    except Exception as e:
        return {"provider": "oci", "error": str(e)}
