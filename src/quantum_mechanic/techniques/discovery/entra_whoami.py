# ================================================================
# TECHNIQUE: discovery/entra_whoami
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087.004 — Cloud Account Discovery
#
# PURPOSE:   Deep Entra ID identity enumeration via Microsoft Graph.
#            Goes beyond basic whoami to enumerate group memberships,
#            directory roles, conditional access posture, and token
#            material summary.
#
# PROVIDERS: Entra
#
# HOW IT WORKS:
#   1. Resolves the best available Graph access token from the
#      EntraTokenStore (direct access token or FOCI-expanded RT).
#   2. Calls Graph /me for base identity.
#   3. Calls Graph /me/memberOf for group memberships.
#   4. Calls Graph /me/transitiveMemberOf/microsoft.graph.directoryRole
#      for Entra directory role assignments (Global Admin, etc.).
#   5. Returns a summary including token posture: FOCI coverage,
#      device claim status, MFA auth methods, and CAP risk surface.
#
# DETECTION (Blue Team):
#   Entra Sign-in Logs: Non-interactive token acquisitions.
#   Graph Audit Logs: Microsoft.Graph/me/read,
#     Microsoft.Graph/me/memberOf/read,
#     Microsoft.Graph/directoryRoles/read.
#   Alert on: Rapid enumeration of /me/memberOf by unfamiliar
#     clientId or from unexpected IP / user-agent.
#
# SAFE:     Yes — read-only Graph queries. No state changes.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.entra.foci import foci_expand
from quantum_mechanic.providers.entra.token_store import GRAPH, EntraTokenStore, decode_jwt_claims

logger = logging.getLogger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_ME            = f"{_GRAPH_BASE}/me"
_ME_MEMBER_OF  = f"{_GRAPH_BASE}/me/memberOf?$top=100"
_ME_DIR_ROLES  = (
    f"{_GRAPH_BASE}/me/transitiveMemberOf/microsoft.graph.directoryRole"
    "?$select=id,displayName,roleTemplateId"
)
_ME_OWNED = f"{_GRAPH_BASE}/me/ownedObjects?$select=id,displayName,appId,@odata.type"


# ----------------------------------------------------------------
# Formatter
# ----------------------------------------------------------------

def _format_entra_whoami(result: Any) -> None:
    from rich.panel import Panel
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    if not isinstance(data, dict):
        return

    me = data.get("me", {})
    upn = me.get("userPrincipalName") or me.get("mail") or data.get("principal_id", "?")
    display = me.get("displayName", upn)
    tenant_id = data.get("tenant_id", "?")

    # ── Identity panel ───────────────────────────────────────────
    lines = [
        f"[bold]Identity:[/bold]   {display} ({upn})",
        f"[bold]Tenant:[/bold]     {tenant_id}",
        f"[bold]Object ID:[/bold]  {me.get('id', '?')}",
        f"[bold]Job Title:[/bold]  {me.get('jobTitle') or '—'}",
        f"[bold]Department:[/bold] {me.get('department') or '—'}",
    ]

    # Token posture
    posture = data.get("posture", {})
    lines.append("")
    lines.append("[bold]Token Posture:[/bold]")
    mfa = posture.get("mfa")
    mfa_str = "[green]verified[/green]" if mfa else ("[red]not in token[/red]" if mfa is False else "[dim]unknown[/dim]")
    device = posture.get("device_claims")
    device_str = "[green]yes[/green]" if device else "[dim]no[/dim]"
    foci = posture.get("foci_token")
    foci_str = "[cyan]yes (family refresh)[/cyan]" if foci else "[dim]no[/dim]"
    lines.append(f"  MFA in token:   {mfa_str}")
    lines.append(f"  Device claims:  {device_str}")
    lines.append(f"  FOCI token:     {foci_str}")

    console.print(Panel("\n".join(lines), title="[bold]Entra ID Identity[/bold]", border_style="green", expand=False))

    # ── Directory Roles ──────────────────────────────────────────
    roles = data.get("directory_roles", [])
    if roles:
        console.print("\n  [bold red]⚠  Directory Roles[/bold red]")
        for r in roles:
            console.print(f"    [bold]{r.get('displayName', '?')}[/bold]  [dim]({r.get('id', '')})[/dim]")
    else:
        console.print("\n  [dim]No directory roles assigned.[/dim]")

    # ── Group memberships ────────────────────────────────────────
    groups = data.get("groups", [])
    if groups:
        tbl = Table(title=f"Group Memberships ({len(groups)})", box=None, padding=(0, 2))
        tbl.add_column("Display Name", style="white")
        tbl.add_column("Type", style="dim")
        tbl.add_column("ID", style="dim")
        for g in groups[:30]:
            odata = g.get("@odata.type", "").replace("#microsoft.graph.", "")
            tbl.add_row(g.get("displayName", "?"), odata, g.get("id", ""))
        console.print(tbl)
        if len(groups) > 30:
            console.print(f"  [dim]... and {len(groups) - 30} more groups[/dim]")
    else:
        console.print("  [dim]No group memberships found.[/dim]")

    # ── Owned objects (escalation paths) ────────────────────────
    owned = data.get("owned_objects", [])
    if owned:
        own_tbl = Table(title=f"Owned Objects — Escalation Paths ({len(owned)})", box=None, padding=(0, 2))
        own_tbl.add_column("Type", style="dim")
        own_tbl.add_column("Display Name", style="bold green")
        own_tbl.add_column("App ID / ID", style="cyan")
        for o in owned:
            otype = o.get("@odata.type", "").split(".")[-1]
            own_tbl.add_row(otype, o.get("displayName", "—"), o.get("appId") or o.get("id", ""))
        console.print(own_tbl)
        console.print("  [dim]Tip: run escalation/entra_app_creds on an owned Application to escalate.[/dim]")


# ----------------------------------------------------------------
# Technique
# ----------------------------------------------------------------

@technique(
    technique_id="discovery/entra_whoami",
    tactic="discovery",
    mitre_id="T1087.004",
    providers=["entra"],
    severity="info",
    safe=True,
    description=(
        "Deep Entra ID identity enumeration: base identity, group memberships, "
        "directory roles, and token posture via Microsoft Graph."
    ),
    formatter=_format_entra_whoami,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Enumerate the active Entra ID identity via Microsoft Graph.

    Resolves the best available Graph token from the session and
    calls /me, /me/memberOf, and /me directoryRole endpoints.
    """
    store: EntraTokenStore = ctx.session

    token = store.best_token(GRAPH)
    if token is None:
        return {"error": "No Graph token available. Import or acquire credentials first."}

    if token.token_type == "refresh_token":
        token = foci_expand(store, GRAPH)
        if token is None:
            return {"error": "FOCI expansion for Graph failed — refresh token may be expired."}

    headers = {"Authorization": f"Bearer {token.value}"}

    me: dict[str, Any] = {}
    groups: list[dict[str, Any]] = []
    directory_roles: list[dict[str, Any]] = []
    owned_objects: list[dict[str, Any]] = []

    with httpx.Client(timeout=30) as http:
        # /me
        resp = http.get(_ME, headers=headers)
        if resp.status_code == 200:
            me = resp.json()
        else:
            _check_cap_error(resp, store)

        # /me/memberOf
        resp = http.get(_ME_MEMBER_OF, headers=headers)
        if resp.status_code == 200:
            groups = resp.json().get("value", [])

        # /me/transitiveMemberOf/microsoft.graph.directoryRole
        resp = http.get(_ME_DIR_ROLES, headers=headers)
        if resp.status_code == 200:
            directory_roles = resp.json().get("value", [])

        # /me/ownedObjects — apps and SPs owned by this principal (escalation paths)
        resp = http.get(_ME_OWNED, headers=headers)
        if resp.status_code == 200:
            owned_objects = resp.json().get("value", [])

    claims = token.raw_claims or decode_jwt_claims(token.value)

    # claims["tid"] is decoded straight from the current access token, so
    # it's always the real, authoritative tenant GUID. Prefer it over
    # store.tenant_id, which can still hold the "common" placeholder from
    # an acquisition that didn't pin a specific tenant.
    tenant_id = (
        claims.get("tid", "")
        or me.get("tenantId")
        or store.tenant_id
    )
    if tenant_id and tenant_id != store.tenant_id:
        store.tenant_id = tenant_id

    upn = me.get("userPrincipalName") or store.user_upn or ""
    if upn and not store.user_upn:
        store.user_upn = upn

    amr: list[str] = claims.get("amr", [])
    mfa: bool | None = None
    if amr:
        mfa = "mfa" in amr or "ngcmfa" in amr

    return {
        "principal_id": me.get("id", claims.get("oid", "")),
        "principal_type": "user" if upn else "service_principal",
        "tenant_id": tenant_id,
        "me": me,
        "groups": groups,
        "directory_roles": directory_roles,
        "owned_objects": owned_objects,
        "posture": {
            "mfa": mfa,
            "device_claims": token.device_claims,
            "foci_token": token.foci,
            "token_type": token.token_type,
        },
        "provider": "entra",
    }


def _check_cap_error(resp: httpx.Response, store: EntraTokenStore) -> None:
    try:
        body = resp.json()
        error = body.get("error", {})
        code = error.get("code", "") + " " + error.get("message", "")
        guidance = store.cap_guidance(code)
        if guidance:
            logger.warning("CAP policy blocking access: %s", guidance)
    except Exception as exc:
        logger.debug("Could not parse CAP error from response: %s", exc)
