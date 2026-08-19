# ================================================================
# TECHNIQUE: collection/storage_search
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1530 — Data from Cloud Storage
#
# PURPOSE:   Search for sensitive files (secrets, keys, configs)
#            specifically within cloud object storage buckets.
#
# PROVIDERS: AWS (S3), Azure (Blobs), GCP (GCS), OCI (Object Storage)
#
# HOW IT WORKS:
#   1. Enumerates accessible buckets/containers (or targets a specific one).
#   2. Lists objects in each bucket (up to 1000 per bucket).
#   3. Filters for sensitive patterns in filenames (.env, .pem, etc.).
#   4. Returns a list of high-value "interest" objects.
#
# OPTIONS:
#   target (optional) — A specific bucket or container name to search.
#   regex  (optional) — Custom regex for file matching.
#
# DETECTION (Blue Team):
#   Monitor for high-volume 'ListObjects' or 'GetBucket' calls.
#   Alert: Cross-bucket enumeration from a non-privileged identity.
#
# SAFE:     Yes — read-only enumeration of cloud-native file storage.
# ================================================================

from __future__ import annotations

import logging
import re
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

# Default sensitive patterns
DEFAULT_PATTERN = (
    r"(\.env|id_rsa|id_dsa|\.pem|config.*\.json|secret|password|db\.sqlite|backup.*\.zip)"
)

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "hits"
LOOT_SCHEMA = [
    ("bucket", "Bucket/Container", "bold cyan"),
    ("key", "Object Key", "white"),
    ("size", "Size", "dim"),
    ("type", "Matched Pattern", "yellow"),
]


@technique(
    technique_id="collection/storage_search",
    tactic="collection",
    mitre_id="T1530",
    providers=["aws", "azure", "gcp", "oci"],
    severity="medium",
    safe=True,
    description="Search for secrets and credentials in cloud object storage (S3, Blobs, GCS).",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "target",
            "A specific bucket or container to search.",
            required=False,
            example="prod-backups",
        ),
        Parameter(
            "regex", "Custom regex for file matching.", default=DEFAULT_PATTERN, example=".*\\.key$"
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute bucket search across cloud providers."""
    if ctx.provider_name == "aws":
        return _search_aws(ctx)
    if ctx.provider_name == "azure":
        return _search_azure(ctx)
    if ctx.provider_name == "gcp":
        return _search_gcp(ctx)
    if ctx.provider_name == "oci":
        return _search_oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "hits": []}


def _search_aws(ctx: ExecutionContext) -> dict[str, Any]:
    s3 = ctx.session.client("s3")
    pattern = ctx.get_param("regex", DEFAULT_PATTERN)
    regex = re.compile(pattern, re.IGNORECASE)

    target_bucket = ctx.get_param("target")
    if target_bucket:
        bucket_names = [target_bucket]
    else:
        try:
            resp = s3.list_buckets()
            bucket_names = [b["Name"] for b in resp.get("Buckets", [])]
        except Exception as e:
            return {"error": f"Failed to list buckets: {e}", "hits": []}

    hits = []
    for bname in bucket_names:
        try:
            ctx.info(f"AWS: searching s3://{bname}...")
            objs = s3.list_objects_v2(Bucket=bname, MaxKeys=1000)
            for obj in objs.get("Contents", []):
                key = obj["Key"]
                if regex.search(key):
                    hits.append(
                        {
                            "bucket": bname,
                            "key": key,
                            "size": obj.get("Size", 0),
                            "type": "Pattern Match",
                        }
                    )
        except Exception as e:
            logger.debug("Skipping bucket %s: %s", bname, e)

    return {"hits": hits, "count": len(hits), "provider": "aws"}


def _search_azure(ctx: ExecutionContext) -> dict[str, Any]:
    """Search Azure Blob Storage."""
    try:
        from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.subscription import SubscriptionClient
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        return {"error": "azure-mgmt-storage or azure-storage-blob not installed.", "hits": []}

    pattern = ctx.get_param("regex", DEFAULT_PATTERN)
    regex = re.compile(pattern, re.IGNORECASE)
    hits = []

    target = ctx.get_param("target")
    cred = ctx.session

    try:
        # If target is provided, we can try to access it directly even if subscription listing fails
        if target:
            # target can be "account" or "account/container"
            if "/" in target:
                account_name, container_name = target.split("/", 1)
                container_names = [container_name]
            else:
                account_name = target
                container_names = None

            accounts = [(account_name, container_names)]
        else:
            # Discovery mode: list all accounts in all subscriptions
            try:
                sub_client = SubscriptionClient(cred)
                subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]
            except Exception as e:
                return {"error": f"Failed to list subscriptions: {e}", "hits": []}

            accounts = []
            for sub_id in subscriptions:
                try:
                    storage_client = StorageManagementClient(cred, sub_id)
                    for account in storage_client.storage_accounts.list():
                        accounts.append((account.name, None))
                except Exception as e:
                    ctx.warn(f"Failed to list storage accounts in subscription {sub_id}: {e}")

        for account_name, container_names in accounts:
            url = f"https://{account_name}.blob.core.windows.net"
            try:
                blob_service = BlobServiceClient(url, credential=cred)

                if container_names is None:
                    # List all containers we can see
                    try:
                        containers = [c.name for c in blob_service.list_containers()]
                    except ClientAuthenticationError:
                        ctx.warn(
                            f"Access denied listing containers for account {account_name}. (Try granting 'Storage Blob Data Reader')"
                        )
                        continue
                    except Exception as e:
                        logger.debug("Failed to list containers for %s: %s", account_name, e)
                        continue
                else:
                    containers = container_names

                for cname in containers:
                    ctx.info(f"Azure: searching {account_name}/{cname}...")
                    try:
                        container_client = blob_service.get_container_client(cname)
                        for blob in container_client.list_blobs(max_results=1000):
                            if regex.search(blob.name):
                                hits.append(
                                    {
                                        "bucket": f"{account_name}/{cname}",
                                        "key": blob.name,
                                        "size": blob.size,
                                        "type": "Pattern Match",
                                    }
                                )
                    except ResourceNotFoundError:
                        ctx.warn(f"Container {cname} not found in account {account_name}.")
                    except ClientAuthenticationError:
                        ctx.warn(f"Access denied listing blobs in {account_name}/{cname}.")
                    except Exception as inner_e:
                        logger.debug(
                            "Error searching container %s/%s: %s", account_name, cname, inner_e
                        )

            except Exception as account_e:
                logger.debug("Failed to connect to storage account %s: %s", account_name, account_e)

        return {"hits": hits, "count": len(hits), "provider": "azure"}
    except Exception as e:
        return {"error": str(e), "hits": []}


def _search_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """Search Google Cloud Storage buckets."""
    try:
        from googleapiclient.discovery import build
    except ImportError:
        return {"error": "google-api-python-client not installed.", "hits": []}

    pattern = ctx.get_param("regex", DEFAULT_PATTERN)
    regex = re.compile(pattern, re.IGNORECASE)
    hits = []

    try:
        project = ctx.whoami().account_id
        if not project:
            return {"error": "Could not determine GCP project ID.", "hits": []}

        storage = build("storage", "v1", credentials=ctx.session)
        buckets_resp = storage.buckets().list(project=project).execute()

        for bucket in buckets_resp.get("items", []):
            bname = bucket["name"]
            ctx.info(f"GCP: searching gs://{bname}...")
            try:
                objs_resp = storage.objects().list(bucket=bname, maxResults=1000).execute()
                for obj in objs_resp.get("items", []):
                    key = obj["name"]
                    if regex.search(key):
                        hits.append(
                            {
                                "bucket": bname,
                                "key": key,
                                "size": int(obj.get("size", 0)),
                                "type": "Pattern Match",
                            }
                        )
            except Exception as inner_e:
                logger.debug("Skipping GCP bucket %s: %s", bname, inner_e)

        return {"hits": hits, "count": len(hits), "provider": "gcp"}
    except Exception as e:
        return {"error": str(e), "hits": []}


def _search_oci(ctx: ExecutionContext) -> dict[str, Any]:
    """Search OCI Object Storage."""
    try:
        import oci
    except ImportError:
        return {"error": "oci not installed.", "hits": []}

    pattern = ctx.get_param("regex", DEFAULT_PATTERN)
    regex = re.compile(pattern, re.IGNORECASE)
    hits = []

    try:
        config = ctx.session["config"]
        signer = ctx.session.get("signer")
        identity = (
            oci.identity.IdentityClient(config={}, signer=signer)
            if signer
            else oci.identity.IdentityClient(config)
        )
        os_client = (
            oci.object_storage.ObjectStorageClient(config={}, signer=signer)
            if signer
            else oci.object_storage.ObjectStorageClient(config)
        )

        tenancy_id = config.get("tenancy")

        compartment_ids = [tenancy_id]
        try:
            child_compartments = identity.list_compartments(
                tenancy_id, compartment_id_in_subtree=True, access_level="ACCESSIBLE"
            ).data
            compartment_ids += [c.id for c in child_compartments]
        except Exception as e:
            logger.debug("Failed listing child compartments: %s", e)

        namespace = os_client.get_namespace().data

        for cid in compartment_ids:
            try:
                buckets = os_client.list_buckets(namespace, cid).data
                for bucket in buckets:
                    bname = bucket.name
                    ctx.info(f"OCI: searching bucket {bname}...")
                    objects = os_client.list_objects(
                        namespace, bname, fields="size", limit=1000
                    ).data
                    for obj in objects.objects:
                        if regex.search(obj.name):
                            hits.append(
                                {
                                    "bucket": bname,
                                    "key": obj.name,
                                    "size": obj.size,
                                    "type": "Pattern Match",
                                }
                            )
            except Exception as e:
                logger.debug("Failed listing buckets in compartment %s: %s", cid, e)

        return {"hits": hits, "count": len(hits), "provider": "oci"}
    except Exception as e:
        return {"error": str(e), "hits": []}
