# ================================================================
# TECHNIQUE: discovery/enum_keyvaults
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:
#   Identify key-management infrastructure across the cloud
#   environment. These systems define cryptographic trust
#   boundaries, hold keys, and often gate access to secret
#   material or encrypted data.
#
# PROVIDERS: aws, azure, gcp, oci
#
# HOW IT WORKS:
#   AWS   — Enumerates KMS keys and aliases across accessible regions using
#           list_aliases, list_keys, and describe_key.
#   Azure — Requires Microsoft.KeyVault/vaults/read. Enumerates Key Vaults
#           across all accessible subscriptions using
#           KeyVaultManagementClient. Identifies whether the vault uses RBAC
#           or Access Policies.
#   GCP   — Enumerates Cloud KMS key rings across accessible projects using
#           Resource Manager project discovery and KeyManagementServiceClient.
#
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

try:
    from google.cloud import kms_v1, resourcemanager_v3
except ImportError:
    kms_v1 = None  # type: ignore[assignment]
    resourcemanager_v3 = None  # type: ignore[assignment]

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "vaults"
LOOT_SCHEMA = [
    ("name", "Vault Name", "bold cyan"),
    ("location", "Location", "dim"),
    ("public_access", "Public Access", "yellow"),
    ("auth_model", "Auth Model", "white"),
    ("uri", "Vault URI", "dim"),
]


@technique(
    technique_id="discovery/enum_keyvaults",
    tactic="discovery",
    mitre_id="T1580",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Enumerate key-management infrastructure such as KMS and Key Vaults.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific vault name to identify.", required=False),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate key-management infrastructure for the active provider."""
    if ctx.provider_name == "aws":
        return _aws(ctx)
    if ctx.provider_name == "azure":
        return _azure(ctx)
    if ctx.provider_name == "gcp":
        return _gcp(ctx)
    if ctx.provider_name == "oci":
        return _oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "vaults": []}


def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate AWS KMS keys and aliases across accessible regions."""
    target = ctx.get_param("target")
    session = ctx.session
    vaults: list[dict[str, Any]] = []

    try:
        regions = session.get_available_regions("kms")
    except Exception:
        regions = [getattr(session, "region_name", None) or "us-east-1"]

    for region in sorted(set(regions)):
        try:
            kms = session.client("kms", region_name=region)
            aliases_by_key: dict[str, list[str]] = {}

            marker = None
            while True:
                kwargs = {"Marker": marker} if marker else {}
                alias_resp = kms.list_aliases(**kwargs)
                for alias in alias_resp.get("Aliases", []):
                    key_id = alias.get("TargetKeyId")
                    alias_name = alias.get("AliasName")
                    if key_id and alias_name:
                        aliases_by_key.setdefault(key_id, []).append(alias_name)
                if not alias_resp.get("Truncated"):
                    break
                marker = alias_resp.get("NextMarker")

            marker = None
            while True:
                kwargs = {"Marker": marker} if marker else {}
                key_resp = kms.list_keys(**kwargs)
                for entry in key_resp.get("Keys", []):
                    key_id = entry.get("KeyId")
                    if not key_id:
                        continue

                    metadata = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                    alias_names = aliases_by_key.get(key_id, [])
                    display_name = alias_names[0] if alias_names else key_id
                    arn = metadata.get("Arn", "")

                    if target and target not in {display_name, key_id, arn}:
                        continue

                    vaults.append(
                        {
                            "name": display_name,
                            "location": region,
                            "public_access": "Private API",
                            "auth_model": "IAM + Key Policy",
                            "uri": arn,
                            "key_id": key_id,
                            "aliases": alias_names,
                        }
                    )
                if not key_resp.get("Truncated"):
                    break
                marker = key_resp.get("NextMarker")
        except Exception as e:
            ctx.warn(f"Failed to list KMS keys in region {region}: {e}")

    return {
        "provider": "aws",
        "vaults": vaults,
        "total": len(vaults),
    }


def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires Microsoft.KeyVault/vaults/read.
    """
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-keyvault not installed.", "vaults": []}

    target = ctx.get_param("target")
    cred = ctx.session
    vaults = []

    try:
        sub_client = SubscriptionClient(cred)
        subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]
    except Exception as e:
        return {"error": f"Failed to list subscriptions: {e}", "vaults": []}

    for sub_id in subscriptions:
        try:
            kv_client = KeyVaultManagementClient(cred, sub_id)
            for vault in kv_client.vaults.list():
                if target and vault.name != target:
                    continue

                # Extract interesting security properties
                # Note: list() might return a partial object, we may need get() for full props
                full_vault = vault
                if not getattr(vault, "properties", None) or not getattr(
                    vault.properties, "vault_uri", None
                ):
                    try:
                        # Extract RG from ID: /subscriptions/.../resourceGroups/{RG}/...
                        rg = vault.id.split("/")[4]
                        full_vault = kv_client.vaults.get(rg, vault.name)
                    except Exception as e:
                        logger.debug(
                            "Failed to get full vault properties for %s: %s",
                            vault.name,
                            e,
                        )

                props = getattr(full_vault, "properties", None)
                public_access = "Enabled"
                auth_model = "Access Policy"
                uri = ""

                if props:
                    if hasattr(props, "public_network_access"):
                        public_access = props.public_network_access or "Enabled"
                    if getattr(props, "enable_rbac_authorization", False):
                        auth_model = "Azure RBAC"
                    uri = getattr(props, "vault_uri", "")

                vaults.append(
                    {
                        "name": vault.name,
                        "location": vault.location,
                        "public_access": public_access,
                        "auth_model": auth_model,
                        "uri": uri,
                        "subscription_id": sub_id,
                    }
                )
        except Exception as e:
            ctx.warn(f"Failed to list vaults in subscription {sub_id}: {e}")

    return {"provider": "azure", "vaults": vaults, "total": len(vaults)}


def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate Cloud KMS key rings across accessible GCP projects."""
    if kms_v1 is None or resourcemanager_v3 is None:
        return {
            "error": "google-cloud-kms or google-cloud-resource-manager package is not installed.",
            "vaults": [],
        }

    target = ctx.get_param("target")
    whoami_res = ctx.whoami()
    projects: list[str] = []
    vaults: list[dict[str, Any]] = []

    try:
        project_client = resourcemanager_v3.ProjectsClient(credentials=ctx.session)
        for project in project_client.search_projects():
            if getattr(project, "project_id", None):
                projects.append(project.project_id)
    except Exception as e:
        ctx.warn(f"Could not list projects via Resource Manager: {e}")

    if not projects and whoami_res.account_id and whoami_res.account_id != "unknown":
        projects.append(whoami_res.account_id)

    if not projects:
        return {
            "error": "No projects found and no default project available.",
            "vaults": [],
        }

    client = kms_v1.KeyManagementServiceClient(credentials=ctx.session)

    for project_id in sorted(set(projects)):
        try:
            for key_ring in client.list_key_rings(
                request={"parent": f"projects/{project_id}/locations/-"}
            ):
                name = key_ring.name.split("/")[-1]
                if target and name != target:
                    continue

                location = "unknown"
                parts = key_ring.name.split("/")
                if "locations" in parts:
                    location = parts[parts.index("locations") + 1]

                vaults.append(
                    {
                        "name": name,
                        "location": location,
                        "public_access": "Private API",
                        "auth_model": "IAM",
                        "uri": key_ring.name,
                        "project_id": project_id,
                    }
                )
        except Exception as e:
            ctx.warn(f"Failed to list Cloud KMS key rings in project {project_id}: {e}")

    return {
        "provider": "gcp",
        "vaults": vaults,
        "total": len(vaults),
    }


def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement OCI Vault / key enumeration
    return {"provider": "oci", "vaults": [], "note": "OCI implementation pending."}
