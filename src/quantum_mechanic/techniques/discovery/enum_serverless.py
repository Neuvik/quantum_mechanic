# ================================================================
# TECHNIQUE: discovery/enum_serverless
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:
#   Discover serverless functions (Lambda, Azure Functions, Cloud Functions)
#   active in the environment. Serverless compute instances are frequently
#   over-privileged via their attached execution roles or Managed Identities
#   to interact with databases and cloud systems. They also historically
#   suffer from poor secrets management, often layering plaintext API keys
#   and connection strings directly into the function's Environment
#   Variables, allowing attackers to harvest collateral credentials.
#
# PROVIDERS: aws, azure, gcp, oci
#
#
# HOW IT WORKS (AWS):
#   Requires lambda:ListFunctions. The technique iterates through all
#   AWS regions invoking lambda.list_functions(). Extracts the
#   execution Role ARN, Runtime, and Environment Variables
#   (Environment.Variables).
#
# DETECTION (AWS):
#   CloudTrail: ListFunctions. Alert on enumeration across multiple regions
#   if the organization typically operates in a single region.
#
# HOW IT WORKS (AZURE):
#   Requires Microsoft.Web/sites/read and optionally
#   Microsoft.Web/sites/config/Read. Calls
#   WebSiteManagementClient.web_apps.list() filtering for objects
#   where kind contains 'functionapp'. Extracts Managed Identity
#   configurations and attempts to pull list_application_settings() to
#   discover plaintext connection strings.
#
# DETECTION (AZURE):
#   Azure Monitor: Microsoft.Web/sites/read and
#   Microsoft.Web/sites/config/list/action. Pulling App Settings explicitly
#   requires higher privileges (Contributor). Alert on config reads from
#   generic monitoring tools.
#
# HOW IT WORKS (GCP):
#   Requires cloudfunctions.functions.list. Iterates cloudfunctions.pr
#   ojects().locations().functions().list(parent=parent). Extracts the
#   executing serviceAccountEmail and the build/environmentVariables
#   dictionary.
#
# DETECTION (GCP):
#   Cloud Audit Logs: cloudfunctions.functions.list.
#
# HOW IT WORKS (OCI):
#   Requires FUNCTIONS_APPLICATION_INSPECT and
#   FUNCTIONS_FUNCTION_INSPECT. Queries
#   FunctionsManagementClient.list_applications() cross-compartment,
#   iterating into list_functions() for each app to scrape defined
#   trace configs and functions.
#
# DETECTION (OCI):
#   OCI Audit: ListFunctions and ListApplications.
# REFERENCES:
#   - https://attack.mitre.org/techniques/T1580/
#   - https://hackingthe.cloud/aws/avoiding-detection/lambda-persistence/
#
# SAFE:      Yes
# ================================================================


from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema — Declarative table mapping
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'functions'
LOOT_SCHEMA = [
    ('name',           'Function Name', 'bold cyan'),
    ('runtime',        'Runtime',       'dim'),
    ('region',         'Region',        'dim'),
    ('role',           'Execution Identity', 'yellow'),
    ('env_var_count',  'Env Vars',      'white'),
]


@technique(
    technique_id='discovery/enum_serverless',
    tactic='discovery',
    mitre_id='T1580',
    providers=['aws', 'azure', 'gcp', 'oci'],
    severity='medium',
    safe=True,
    description='Enumerate serverless functions, execution identities, and environment variables.',
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Enumerate serverless functions, execution identities, and environment variables.

    Generated from: enum_serverless.yaml
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
    Requires lambda:ListFunctions. The technique iterates through all
    AWS regions invoking lambda.list_functions(). Extracts the execution
    Role ARN, Runtime, and Environment Variables
    (Environment.Variables).

    DETECTION:
    CloudTrail: ListFunctions. Alert on enumeration across multiple
    regions if the organization typically operates in a single region.

    TESTING INFRASTRUCTURE:
    Deploy an AWS Lambda function with a hardcoded Environment Variable
    containing a dummy API key. Attach an execution role (lambda-basic-
    execution). Grant the attacker role lambda:ListFunctions.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires lambda:ListFunctions. The technique iterates through all AWS regions invoking lambda.list_functions(). Extracts the execution Role ARN, Runtime, and Environment Variables (Environment.Variables).
    try:
        from botocore.exceptions import BotoCoreError, ClientError
        ec2 = ctx.session.client("ec2")

        try:
            regions_resp = ec2.describe_regions()
            regions = [r["RegionName"] for r in regions_resp.get("Regions", [])]
        except (BotoCoreError, ClientError):
            regions = ["us-east-1"]

        functions = []
        for region in regions:
            try:
                l_client = ctx.session.client("lambda", region_name=region)
                paginator = l_client.get_paginator("list_functions")
                for page in paginator.paginate():
                    for f in page.get("Functions", []):
                        env_vars = f.get("Environment", {}).get("Variables", {})

                        code_location = None
                        try:
                            # Try to get function details to extract the pre-signed code download URL
                            func_details = l_client.get_function(FunctionName=f.get("FunctionName"))
                            code_location = func_details.get("Code", {}).get("Location")
                        except (BotoCoreError, ClientError):
                            pass

                        functions.append({
                            "name": f.get("FunctionName"),
                            "role": f.get("Role"),
                            "runtime": f.get("Runtime"),
                            "region": region,
                            "env_var_count": len(env_vars),
                            "env_vars": env_vars,
                            "code_location": code_location,
                        })
            except ClientError:
                pass

        return {
            "provider": "aws",
            "functions": functions,
            "total": len(functions)
        }
    except Exception as e:
        return {"provider": "aws", "error": str(e)}
def _azure(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires Microsoft.Web/sites/read and optionally
    Microsoft.Web/sites/config/Read. Calls
    WebSiteManagementClient.web_apps.list() filtering for objects where
    kind contains 'functionapp'. Extracts Managed Identity
    configurations and attempts to pull list_application_settings() to
    discover plaintext connection strings.

    DETECTION:
    Azure Monitor: Microsoft.Web/sites/read and
    Microsoft.Web/sites/config/list/action. Pulling App Settings
    explicitly requires higher privileges (Contributor). Alert on config
    reads from generic monitoring tools.

    TESTING INFRASTRUCTURE:
    Create an Azure FunctionApp with a SystemAssigned Managed Identity
    and custom Configuration App Settings. Grant attacker principal Web
    Plan Contributor.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires Microsoft.Web/sites/read and optionally Microsoft.Web/sites/config/Read. Calls WebSiteManagementClient.web_apps.list() filtering for objects where kind contains 'functionapp'. Extracts Managed Identity configurations and attempts to pull list_application_settings() to discover plaintext connection strings.
    try:
        from azure.mgmt.subscription import SubscriptionClient
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError:
        return {"error": "azure-mgmt-web not installed.", "functions": []}

    try:
        cred = ctx.session
        sub_client = SubscriptionClient(cred)
        subscriptions = [s.subscription_id for s in sub_client.subscriptions.list()]

        functions = []
        for sub_id in subscriptions:
            web_client = WebSiteManagementClient(cred, sub_id)
            try:
                for app in web_client.web_apps.list():
                    kind = app.kind or ""
                    if "functionapp" not in kind.lower():
                        continue

                    identity = app.identity
                    identity_type = (
                        identity.type.value if hasattr(identity.type, "value") else str(identity.type)
                    ) if identity and getattr(identity, "type", None) else "None"

                    env_vars: dict = {}
                    try:
                        parts = (app.id or "").split("/")
                        rg = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else None
                        if rg:
                            settings = web_client.web_apps.list_application_settings(rg, app.name)
                            env_vars = settings.properties or {}
                    except Exception:
                        pass

                    functions.append({
                        "name": app.name,
                        "runtime": kind,
                        "region": app.location,
                        "role": identity_type,
                        "env_var_count": len(env_vars),
                        "env_vars": env_vars,
                    })
            except Exception as e:
                logger.warning("Failed to enumerate Function Apps in subscription %s: %s", sub_id, e)

        return {"provider": "azure", "functions": functions, "total": len(functions)}
    except Exception as e:
        return {"error": str(e), "functions": []}
def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires cloudfunctions.functions.list. Iterates cloudfunctions.proj
    ects().locations().functions().list(parent=parent). Extracts the
    executing serviceAccountEmail and the build/environmentVariables
    dictionary.

    DETECTION:
    Cloud Audit Logs: cloudfunctions.functions.list.

    TESTING INFRASTRUCTURE:
    Deploy a Cloud Function (Gen1 or Gen2) with an attached non-default
    Service Account and dummy environment variables. Give the attacker
    SA roles/cloudfunctions.viewer.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires cloudfunctions.functions.list. Iterates cloudfunctions.projects().locations().functions().list(parent=parent). Extracts the executing serviceAccountEmail and the build/environmentVariables dictionary.
    return {"error": "GCP serverless enumeration not yet implemented.", "functions": []}
def _oci(ctx: ExecutionContext) -> dict[str, Any]:
    """
    Requires FUNCTIONS_APPLICATION_INSPECT and
    FUNCTIONS_FUNCTION_INSPECT. Queries
    FunctionsManagementClient.list_applications() cross-compartment,
    iterating into list_functions() for each app to scrape defined trace
    configs and functions.

    DETECTION:
    OCI Audit: ListFunctions and ListApplications.

    TESTING INFRASTRUCTURE:
    Provision an OCI Application containing one Function. Grant attacker
    user inspect functions privilege.
    """
    # -----------------------------------------------------------------
    # Implementation steps (from attack map):
    # -----------------------------------------------------------------
    # Requires FUNCTIONS_APPLICATION_INSPECT and FUNCTIONS_FUNCTION_INSPECT. Queries FunctionsManagementClient.list_applications() cross-compartment, iterating into list_functions() for each app to scrape defined trace configs and functions.
    return {"error": "OCI serverless enumeration not yet implemented.", "functions": []}

