# ================================================================
# TECHNIQUE: collection/get_keyvault_secrets
# ----------------------------------------------------------------
# TACTIC:    Collection (TA0009)
# TECHNIQUE: T1530 — Data from Cloud Storage (Applied to Secrets)
#
# PURPOSE:
#   Compatibility wrapper for the legacy cross-provider secret
#   retrieval surface. The canonical long-term surface is
#   `collection/get_secrets`.
#
# PROVIDERS: aws, azure, gcp, oci
#
# SAFE:      Yes
# ================================================================

from __future__ import annotations

from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique
from quantum_mechanic.techniques.collection.get_secrets import (
    LOOT_ITEMS_KEY,
    LOOT_SCHEMA,
    run_secret_collection,
)


@technique(
    technique_id="collection/get_keyvault_secrets",
    tactic="collection",
    mitre_id="T1530",
    providers=["aws", "azure", "gcp", "oci"],
    severity="high",
    safe=True,
    description="Compatibility wrapper for retrieving secrets from Key Vaults and Secret Managers.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific vault or manager to search.", required=False),
        Parameter("secret_name", "A specific secret name to retrieve.", required=False),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Run the legacy get_keyvault_secrets surface via the canonical handler."""
    return run_secret_collection(ctx)
