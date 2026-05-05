# ================================================================
# TECHNIQUE: discovery/enum_keyvaults
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:
#   Identify secret management services (Key Vaults, Secrets Manager)
#   across the cloud environment. These services are high-value
#   targets as they often contain API keys, database passwords,
#   and encryption keys.
#
# PROVIDERS: aws, azure, gcp, oci
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.KeyVault/vaults/read. Enumerates Key Vaults
#   across all accessible subscriptions using KeyVaultManagementClient.
#   Identifies whether the vault uses RBAC or Access Policies.
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
LOOT_ITEMS_KEY = 'vaults'
LOOT_SCHEMA = [
    ('name',           'Vault Name',      'bold cyan'),
    ('location',       'Location',        'dim'),
    ('public_access',  'Public Access',   'yellow'),
    ('auth_model',     'Auth Model',      'white'),
    ('uri',            'Vault URI',       'dim'),
]

@technique(
    technique_id='discovery/enum_keyvaults',
    tactic='discovery',
    mitre_id='T1580',
    providers=['aws', 'azure', 'gcp', 'oci'],
    severity='info',
    safe=True,
    description='Enumerate secret management services (Azure Key Vault, AWS Secrets Manager, etc.)',
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific vault name to identify.", required=False),
    ]
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate key vaults and secret managers."""
    if ctx.provider_name == 'aws':
        return _aws(ctx)
    if ctx.provider_name == 'azure':
        return _azure(ctx)
    if ctx.provider_name == 'gcp':
        return _gcp(ctx)
    if ctx.provider_name == 'oci':
        return _oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "vaults": []}

def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement AWS Secrets Manager/KMS enumeration
    return {"provider": "aws", "vaults": [], "note": "AWS implementation pending."}

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
                if not getattr(vault, "properties", None) or not getattr(vault.properties, "vault_uri", None):
                    try:
                        # Extract RG from ID: /subscriptions/.../resourceGroups/{RG}/...
                        rg = vault.id.split("/")[4]
                        full_vault = kv_client.vaults.get(rg, vault.name)
                    except Exception: pass

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

                vaults.append({
                    "name": vault.name,
                    "location": vault.location,
                    "public_access": public_access,
                    "auth_model": auth_model,
                    "uri": uri,
                    "subscription_id": sub_id
                })
        except Exception as e:
            ctx.warn(f"Failed to list vaults in subscription {sub_id}: {e}")

    return {
        "provider": "azure",
        "vaults": vaults,
        "total": len(vaults)
    }

def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement GCP Secret Manager enumeration
    return {"provider": "gcp", "vaults": [], "note": "GCP implementation pending."}

def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    # TODO: Implement OCI Vault enumeration
    return {"provider": "oci", "vaults": [], "note": "OCI implementation pending."}
