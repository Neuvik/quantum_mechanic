# ================================================================
# TECHNIQUE: discovery/enum_secrets
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:
#   Identify secret-store inventory across the cloud environment.
#   These systems hold retrievable credentials, API keys,
#   connection strings, and other high-value application secrets.
#
# PROVIDERS: aws, gcp
#
# HOW IT WORKS:
#   AWS   — Enumerates AWS Secrets Manager secrets across accessible regions.
#   GCP   — Enumerates Secret Manager secrets across accessible projects
#           using Resource Manager project discovery plus the
#           SecretManagerServiceClient control plane. This is inventory
#           only; secret values are retrieved by collection techniques.
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
    from google.cloud import resourcemanager_v3, secretmanager
except ImportError:
    resourcemanager_v3 = None  # type: ignore[assignment]
    secretmanager = None  # type: ignore[assignment]

LOOT_ITEMS_KEY = "secrets"
LOOT_SCHEMA = [
    ("scope", "Scope", "dim"),
    ("name", "Secret Name", "bold cyan"),
    ("backend", "Backend", "white"),
    ("uri", "Resource Name", "dim"),
]


@technique(
    technique_id="discovery/enum_secrets",
    tactic="discovery",
    mitre_id="T1580",
    providers=["aws", "gcp"],
    severity="info",
    safe=True,
    description="Enumerate secret-store inventory such as GCP Secret Manager secrets.",
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter("target", "A specific secret name to identify.", required=False),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate secret-store inventory for the active provider."""
    if ctx.provider_name == "aws":
        return _aws(ctx)
    if ctx.provider_name == "gcp":
        return _gcp(ctx)

    return {"error": f"Provider {ctx.provider_name} not implemented.", "secrets": []}


def _aws(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate AWS Secrets Manager inventory across accessible regions."""
    target = ctx.get_param("target")
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

                    secrets.append(
                        {
                            "scope": region,
                            "name": name,
                            "backend": "Secrets Manager",
                            "uri": arn,
                        }
                    )

                next_token = response.get("NextToken")
                if not next_token:
                    break
        except Exception as e:
            ctx.warn(f"Failed to list Secrets Manager inventory in region {region}: {e}")

    return {
        "provider": "aws",
        "secrets": secrets,
        "total": len(secrets),
    }


def _gcp(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate GCP Secret Manager inventory across accessible projects."""
    if secretmanager is None or resourcemanager_v3 is None:
        return {
            "error": (
                "google-cloud-secret-manager or google-cloud-resource-manager "
                "package is not installed."
            ),
            "secrets": [],
        }

    target = ctx.get_param("target")
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
                name = secret.name.split("/")[-1]
                if target and name != target:
                    continue

                replication = "unknown"
                replication_cfg = getattr(secret, "replication", None)
                if replication_cfg is not None:
                    if getattr(replication_cfg, "automatic", None) is not None:
                        replication = "automatic"
                    elif getattr(replication_cfg, "user_managed", None) is not None:
                        replication = "user-managed"

                secrets.append(
                    {
                        "scope": project_id,
                        "name": name,
                        "backend": f"Secret Manager ({replication})",
                        "uri": secret.name,
                    }
                )
        except Exception as e:
            ctx.warn(f"Failed to list Secret Manager secrets in project {project_id}: {e}")

    return {
        "provider": "gcp",
        "secrets": secrets,
        "total": len(secrets),
    }
