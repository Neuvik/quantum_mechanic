# ================================================================
# MODULE: quantum_mechanic.shell.commands_entra
# ----------------------------------------------------------------
# PURPOSE:   Shell command handlers for the Entra ID identity
#            pipeline: import, acquire, and export sub-commands.
#
#            import entra  — ingest token material (EI-3)
#            acquire entra — active OAuth acquisition (EI-4)
#            export entra  — roadtools interop + introspection (EI-5)
# ================================================================

from __future__ import annotations

import json
import logging
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from quantum_mechanic.shell.commands import ShellState

logger = logging.getLogger(__name__)
console = Console()

_GRAPH   = "https://graph.microsoft.com"
_ARM     = "https://management.azure.com"

_IMPORT_USAGE = """\
  Usage: import entra <subcommand> [args]

  [bold]`import entra` is for EXISTING artifacts you already have.[/bold]
  For fresh authentication (no artifact to hand off), use [cyan]acquire entra[/cyan] — see below.

  Import subcommands:
    browserdump <path>                              Parse browserdump JSON output
    roadtools   <path>                              Import .roadtools_auth file
    access_token <jwt>                              Raw JWT access token
    refresh_token <token> --tenant <id>             Raw refresh token
                          [--client <id>]
    prt_cookie  <jwt>                               x-ms-RefreshTokenCredential (exchanges immediately)
    ests_cookie <value>   --tenant <id>             ESTSAUTHPERSISTENT / ESTSAUTH cookie
    prt_key               --prt <val>               Raw PRT + session key (no expiry pressure)
                          --session-key <key>
                          --tenant <id>
    help                                            Print this usage

  Don't have an artifact? Get one via live authentication:
    [cyan]acquire entra device_code[/cyan]                    Phone-verify OAuth (no local az session needed)
    [cyan]acquire entra interactive[/cyan]                    Browser OAuth (survives Conditional Access)
    [cyan]acquire entra ropc[/cyan] --username <u> --password <p> --tenant <t>
                                             Username+password → FOCI RT
    Then: [cyan]acquire entra arm[/cyan] / [cyan]acquire entra refresh --resource <res>[/cyan]
                                             Pivot to ARM or another Graph scope
"""

_ACQUIRE_USAGE = """\
  Usage: acquire entra <subcommand> [args]

  Subcommands:
    device_code  [--client <id>] [--resource <res>] [--tenant <id>]
    interactive  [--tenant <id>] [--client <id>] [--resource <res>]
                 [--timeout <secs>]
    ropc         --username <upn> --password <pass> --tenant <id>
                 [--resource <res>]
    refresh      [--resource <res>] [--client <id>]
    arm                                              Pivot to Azure ARM via FOCI
    certificate  --pfx <path> --password <pw> --client <id> --tenant <id>
                 [--resource <res>]

  --client also accepts a short alias instead of a raw GUID:
    office | vs-legacy | az-cli | az-ps | graph-cli
"""

_EXPORT_USAGE = """\
  Usage: export entra <subcommand> [args]

  Subcommands:
    roadtools  [--resource <res>]   Write .roadtools_auth to current directory
    token      [--resource <res>]   Print raw access token to stdout
    describe   [--resource <res>]   Decode and display all JWT claims
"""


# ================================================================
# import entra
# ================================================================

def import_entra(state: ShellState, args: list[str]) -> None:
    """Dispatch: import entra <subcommand> ..."""
    if not args:
        console.print(_IMPORT_USAGE)
        return

    sub  = args[0].lower()
    rest = args[1:]
    opts = _parse_opts(rest)

    if sub in ("help", "--help", "-h", "?"):
        console.print(_IMPORT_USAGE)
    elif sub == "browserdump":
        _import_browserdump(state, rest, opts)
    elif sub == "roadtools":
        _import_roadtools(state, rest, opts)
    elif sub == "access_token":
        _import_access_token(state, rest, opts)
    elif sub == "refresh_token":
        _import_refresh_token(state, rest, opts)
    elif sub == "prt_cookie":
        _import_prt_cookie(state, rest, opts)
    elif sub == "ests_cookie":
        _import_ests_cookie(state, rest, opts)
    elif sub == "prt_key":
        _import_prt_key(state, rest, opts)
    else:
        console.print(f"  [red]✗[/red] Unknown subcommand: {sub}")
        console.print(_IMPORT_USAGE)


def _import_browserdump(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.exchange import (
        exchange_ests_cookie,
        exchange_prt_cookie,
    )
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT
    from quantum_mechanic.providers.entra.ingest import ingest_browserdump

    path = args[0] if args else opts.get("path", "")
    if not path:
        console.print("  [red]✗[/red] Path required: import entra browserdump <path>")
        return

    try:
        stores = ingest_browserdump(path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"  [red]✗[/red] Could not read browserdump file: {e}")
        return

    if not stores:
        console.print("  [yellow]⚠[/yellow]  No recognised Entra tokens found in file.")
        return

    for store in stores:
        # Exchange time-sensitive PRT cookies immediately.
        prt = store.prt_cookie()
        if prt and not prt.is_expired:
            mins = prt.minutes_remaining
            console.print(
                "  [yellow]⚡[/yellow] PRT cookie detected"
                + (f" — {mins:.1f}m remaining. Exchanging now..." if mins else " — exchanging now...")
            )
            tenant = store.tenant_id or prt.tenant_id or "common"
            resp = exchange_prt_cookie(
                prt.value,
                tenant_id=tenant,
                client_id=FOCI_DEFAULT_CLIENT,
                resource=_GRAPH,
            )
            _apply_token_response(store, resp, resource=_GRAPH, client_id=FOCI_DEFAULT_CLIENT)

        elif prt and prt.is_expired:
            console.print("  [red]✗[/red] PRT cookie has expired (nonce window passed).")

        # Exchange ESTS cookies.
        for tok in [t for t in store.tokens if t.token_type == "ests_cookie" and t.value]:
            tenant = store.tenant_id or tok.tenant_id or "common"
            resp = exchange_ests_cookie(
                tok.value,
                tenant_id=tenant,
                client_id=FOCI_DEFAULT_CLIENT,
                resource=_GRAPH,
            )
            if "access_token" in resp:
                _apply_token_response(
                    store, resp, resource=_GRAPH, client_id=FOCI_DEFAULT_CLIENT
                )

        cred_id = _persist_store(state, store)
        if cred_id:
            _set_active(state, cred_id, store)
            _print_import_summary(store, cred_id)


def _import_roadtools(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.ingest import ingest_roadtools

    path = args[0] if args else opts.get("path", "")
    if not path:
        console.print("  [red]✗[/red] Path required: import entra roadtools <path>")
        return

    try:
        store = ingest_roadtools(path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        console.print(f"  [red]✗[/red] Could not read roadtools file: {e}")
        return

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _import_access_token(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.ingest import ingest_access_token

    jwt = args[0] if args else opts.get("token", "")
    if not jwt:
        console.print("  [red]✗[/red] JWT required: import entra access_token <jwt>")
        return

    resource = opts.get("resource", _GRAPH)
    tok = ingest_access_token(jwt, resource=resource)

    store = EntraTokenStore(tenant_id=tok.tenant_id, user_upn=tok.raw_claims.get("upn"))
    store.add_token(tok)

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _import_refresh_token(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.foci import resolve_client_alias
    from quantum_mechanic.providers.entra.ingest import ingest_refresh_token

    token = args[0] if args else opts.get("token", "")
    if not token:
        console.print(
            "  [red]✗[/red] Token required: import entra refresh_token <token> --tenant <id>"
        )
        return

    tenant_id = opts.get("tenant")
    client_id = resolve_client_alias(opts.get("client"))
    if not tenant_id:
        console.print("  [red]✗[/red] --tenant is required for refresh_token import")
        return

    tok = ingest_refresh_token(token, tenant_id=tenant_id, client_id=client_id)
    store = EntraTokenStore(tenant_id=tenant_id)
    store.add_token(tok)

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _import_prt_cookie(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.exchange import exchange_prt_cookie
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT, resolve_client_alias
    from quantum_mechanic.providers.entra.ingest import ingest_prt_cookie

    jwt = args[0] if args else opts.get("token", "")
    if not jwt:
        console.print("  [red]✗[/red] JWT required: import entra prt_cookie <jwt>")
        return

    tok = ingest_prt_cookie(jwt)

    if tok.is_expired:
        console.print("  [red]✗[/red] PRT cookie has expired. The nonce window (~5 min) has passed.")
        return

    mins = tok.minutes_remaining
    console.print(
        "  [yellow]⚡[/yellow] PRT cookie detected"
        + (f" — {mins:.1f}m remaining. Exchanging now..." if mins else " — exchanging now...")
    )

    tenant = tok.tenant_id or opts.get("tenant", "common")
    client_id = resolve_client_alias(opts.get("client")) or FOCI_DEFAULT_CLIENT
    resource = opts.get("resource", _GRAPH)

    resp = exchange_prt_cookie(
        jwt, tenant_id=tenant, client_id=client_id, resource=resource
    )

    store = EntraTokenStore(tenant_id=tenant)
    store.add_token(tok)
    _apply_token_response(store, resp, resource=resource, client_id=client_id)

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _import_ests_cookie(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.exchange import exchange_ests_cookie
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT, resolve_client_alias
    from quantum_mechanic.providers.entra.ingest import ingest_ests_cookie

    value = args[0] if args else opts.get("value", "")
    if not value:
        console.print(
            "  [red]✗[/red] Cookie value required: import entra ests_cookie <value> --tenant <id>"
        )
        return

    tenant = opts.get("tenant", "common")
    client_id = resolve_client_alias(opts.get("client")) or FOCI_DEFAULT_CLIENT
    resource = opts.get("resource", _GRAPH)

    tok = ingest_ests_cookie(value, tenant_id=tenant)
    store = EntraTokenStore(tenant_id=tenant)
    store.add_token(tok)

    console.print("  Exchanging ESTS cookie for tokens...")
    resp = exchange_ests_cookie(
        value, tenant_id=tenant, client_id=client_id, resource=resource
    )
    _apply_token_response(store, resp, resource=resource, client_id=client_id)

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _import_prt_key(
    state: ShellState,
    args: list[str],
    opts: dict[str, str],
) -> None:
    from quantum_mechanic.providers.entra.ingest import ingest_prt_key

    prt_val = opts.get("prt", "")
    session_key = opts.get("session-key", "")
    tenant = opts.get("tenant", "")

    if not prt_val or not session_key or not tenant:
        console.print(
            "  [red]✗[/red] Required: --prt <value> --session-key <key> --tenant <id>"
        )
        return

    tok = ingest_prt_key(prt_val, session_key, tenant_id=tenant)
    store = EntraTokenStore(tenant_id=tenant)
    store.add_token(tok)

    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        console.print(
            f"  [green]✓[/green] PRT + session key stored (credential #{cred_id}). "
            "No expiry pressure — mint PRT cookies on demand."
        )


# ================================================================
# acquire entra  (EI-4)
# ================================================================

def acquire_entra(state: ShellState, args: list[str]) -> None:
    """Dispatch: acquire entra <subcommand> ..."""
    if not args:
        console.print(_ACQUIRE_USAGE)
        return

    sub  = args[0].lower()
    rest = args[1:]
    opts = _parse_opts(rest)

    if sub in ("help", "--help", "-h", "?"):
        console.print(_ACQUIRE_USAGE)
    elif sub == "device_code":
        _acquire_device_code(state, opts)
    elif sub == "interactive":
        _acquire_interactive(state, opts)
    elif sub == "ropc":
        _acquire_ropc(state, opts)
    elif sub == "refresh":
        _acquire_refresh(state, opts)
    elif sub == "arm":
        _acquire_arm(state, opts)
    elif sub == "certificate":
        console.print("  [yellow]⚠[/yellow]  Certificate auth not yet implemented.")
    elif sub == "device_enroll":
        console.print("  [yellow]⚠[/yellow]  Device enrollment not yet implemented.")
    else:
        console.print(f"  [red]✗[/red] Unknown subcommand: {sub}")
        console.print(_ACQUIRE_USAGE)


def _acquire_device_code(state: ShellState, opts: dict[str, str]) -> None:
    from quantum_mechanic.providers.entra.exchange import (
        initiate_device_code,
        poll_device_code,
    )
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT, resolve_client_alias

    tenant = opts.get("tenant", "common")
    client_id = resolve_client_alias(opts.get("client")) or FOCI_DEFAULT_CLIENT
    resource = opts.get("resource", _GRAPH)

    console.print("  Initiating device code flow...")
    dc = initiate_device_code(tenant_id=tenant, client_id=client_id, resource=resource)

    if "error" in dc:
        console.print(f"  [red]✗[/red] {dc.get('error_description', dc['error'])}")
        return

    user_code = dc.get("user_code", "")
    verify_url = dc.get("verification_uri", "https://microsoft.com/devicelogin")
    expires_in = dc.get("expires_in", 900)
    interval = dc.get("interval", 5)

    console.print()
    console.print(f"  [bold]URL:[/bold]  {verify_url}")
    console.print(f"  [bold]Code:[/bold] [cyan]{user_code}[/cyan]")
    console.print(f"  [dim]Expires in {expires_in}s. Waiting for approval...[/dim]")
    console.print()

    resp = poll_device_code(
        dc["device_code"],
        tenant_id=tenant,
        client_id=client_id,
        resource=resource,
        interval=interval,
        timeout=expires_in,
    )

    if "error" in resp:
        guidance = _cap_guidance(resp.get("error_description", ""))
        if guidance:
            console.print(guidance)
        else:
            console.print(f"  [red]✗[/red] {resp.get('error_description', resp['error'])}")
        return

    store = _store_from_response(resp, tenant_id=tenant, resource=resource, client_id=client_id)
    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _acquire_interactive(state: ShellState, opts: dict[str, str]) -> None:
    """OAuth authorization-code + PKCE flow (browser).

    Use when Conditional Access blocks the device_code grant type. Opens
    the operator's default browser to the Entra sign-in page; captures
    the redirect on a localhost ephemeral port; exchanges the auth code
    for tokens; persists via the standard EntraTokenStore pipeline.
    """
    from quantum_mechanic.providers.entra.exchange import interactive_authorize
    from quantum_mechanic.providers.entra.foci import (
        INTERACTIVE_DEFAULT_CLIENT,
        resolve_client_alias,
    )

    tenant = opts.get("tenant", "common")
    client_id = resolve_client_alias(opts.get("client")) or INTERACTIVE_DEFAULT_CLIENT
    resource = opts.get("resource", _GRAPH)
    timeout = int(opts.get("timeout", "300"))

    console.print("  Opening browser for interactive sign-in...")
    console.print(
        f"  [dim]Tenant: {tenant}   Client: {client_id[:8]}...   "
        f"Resource: {resource}[/dim]"
    )
    console.print(f"  [dim]Waiting up to {timeout}s for callback...[/dim]")

    resp = interactive_authorize(
        tenant_id=tenant,
        client_id=client_id,
        resource=resource,
        timeout=timeout,
    )

    if "error" in resp:
        guidance = _cap_guidance(resp.get("error_description", ""))
        if guidance:
            console.print(guidance)
        else:
            console.print(f"  [red]✗[/red] {resp.get('error_description', resp['error'])}")
        return

    store = _store_from_response(resp, tenant_id=tenant, resource=resource, client_id=client_id)
    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _acquire_ropc(state: ShellState, opts: dict[str, str]) -> None:
    from quantum_mechanic.providers.entra.exchange import exchange_ropc
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT, resolve_client_alias

    username = opts.get("username", "")
    password = opts.get("password", "")
    tenant   = opts.get("tenant", "")
    if not username or not password or not tenant:
        console.print(
            "  [red]✗[/red] Required: --username <upn> --password <pass> --tenant <id>"
        )
        return

    console.print(
        "  [yellow]⚠[/yellow]  ROPC only works when legacy auth is not blocked "
        "and MFA is not required."
    )

    client_id = resolve_client_alias(opts.get("client")) or FOCI_DEFAULT_CLIENT
    resource  = opts.get("resource", _GRAPH)

    resp = exchange_ropc(
        username, password,
        tenant_id=tenant, client_id=client_id, resource=resource,
    )

    if "error" in resp:
        guidance = _cap_guidance(resp.get("error_description", ""))
        console.print(guidance or f"  [red]✗[/red] {resp.get('error_description', resp['error'])}")
        return

    store = _store_from_response(
        resp, tenant_id=tenant, resource=resource, client_id=client_id
    )
    store.user_upn = username
    cred_id = _persist_store(state, store)
    if cred_id:
        _set_active(state, cred_id, store)
        _print_import_summary(store, cred_id)


def _acquire_refresh(state: ShellState, opts: dict[str, str]) -> None:
    from quantum_mechanic.providers.entra.exchange import exchange_refresh_token
    from quantum_mechanic.providers.entra.foci import FOCI_DEFAULT_CLIENT, resolve_client_alias

    store = _active_entra_store(state)
    if store is None:
        _print_no_entra_cred_guidance(state, "refresh")
        return

    rt = store.refresh_token() or store.foci_refresh_token()
    if rt is None:
        console.print("  [red]✗[/red] No refresh token in active store.")
        return

    resource  = opts.get("resource", _GRAPH)
    client_id = resolve_client_alias(opts.get("client")) or rt.client_id or FOCI_DEFAULT_CLIENT
    tenant    = store.tenant_id or rt.tenant_id or "common"

    # Was there already a live AT for this resource? If so, this is a
    # renewal (level up in place). If not, this is a new pivot and gets
    # its own credential row so the operator can move between them.
    prior = store.best_token(resource)
    is_renewal = (
        prior is not None
        and prior.token_type == "access_token"
        and not prior.is_expired
    )

    resp = exchange_refresh_token(
        rt.value,
        tenant_id=tenant,
        client_id=client_id,
        resource=resource,
    )

    if "error" in resp:
        guidance = _cap_guidance(resp.get("error_description", ""))
        console.print(guidance or f"  [red]✗[/red] {resp.get('error_description', resp['error'])}")
        return

    _apply_token_response(store, resp, resource=resource, client_id=client_id)

    if is_renewal:
        _update_store(state, store)
        console.print(
            f"  [green]✓[/green] Access token renewed for {resource}"
        )
    else:
        parent_id = state.active_credential_id
        # Compact label — strip the https:// prefix so the row stays readable.
        label = resource.replace("https://", "").rstrip("/")
        new_id = _mint_derived_cred(
            state, store,
            label_suffix=f"→ {label}",
            obtained_via=f"acquire entra refresh --resource {resource}",
            new_token_resource=resource,
        )
        if new_id is not None:
            console.print(
                f"  [green]✓[/green] Access token acquired for {resource} — "
                f"stored as credential [bold cyan]#{new_id}[/bold cyan] "
                f"(derived from #{parent_id})"
            )
            console.print(
                f"  [dim]Now active. Use `use {parent_id}` to switch back.[/dim]"
            )
        else:
            _update_store(state, store)
            console.print(
                f"  [green]✓[/green] Access token acquired for {resource}"
            )


def _acquire_arm(state: ShellState, opts: dict[str, str]) -> None:
    """Expand the active FOCI refresh token to an ARM access token.

    On success, mints a NEW credential row derived from the currently-active
    one so operators can `use <original>` / `use <new>` to move between the
    Graph and ARM pivots. If the current cred already has a live ARM AT, we
    do nothing (the operator is already on the pivot they want).
    """
    from quantum_mechanic.providers.entra.foci import foci_expand

    store = _active_entra_store(state)
    if store is None:
        _print_no_entra_cred_guidance(state, "arm")
        return

    existing = store.best_token(_ARM)
    if existing and existing.token_type == "access_token" and not existing.is_expired:
        mins = existing.minutes_remaining
        console.print(
            f"  [green]✓[/green] ARM token already present "
            + (f"({mins:.0f}m remaining)" if mins else "")
        )
        return

    console.print("  Expanding FOCI refresh token to ARM...")
    tok = foci_expand(store, _ARM)
    if tok is None:
        console.print(
            "  [red]✗[/red] FOCI expansion failed. "
            "The refresh token may not support ARM or may be expired."
        )
        return

    parent_id = state.active_credential_id
    new_id = _mint_derived_cred(
        state, store,
        label_suffix="→ ARM",
        obtained_via="acquire entra arm",
        new_token_resource=_ARM,
    )
    if "azure" not in state._extra_providers:
        state._extra_providers.append("azure")

    mins = tok.minutes_remaining
    exp_str = f"  ({mins:.0f}m remaining)" if mins else ""
    if new_id is not None:
        console.print(
            f"  [green]✓[/green] ARM access token acquired — "
            f"stored as credential [bold cyan]#{new_id}[/bold cyan] "
            f"(derived from #{parent_id}){exp_str}"
        )
        console.print(
            "  [dim]Now active. Use `use "
            f"{parent_id}` to switch back to the Graph pivot.[/dim]"
        )
    else:
        # Fallback: no workspace context (shouldn't happen in practice).
        _update_store(state, store)
        console.print(f"  [green]✓[/green] ARM access token acquired{exp_str}")
    console.print(
        "  Azure techniques now visible. Run: [cyan]techniques[/cyan]"
    )


# ================================================================
# export entra  (EI-5)
# ================================================================

def export_entra(state: ShellState, args: list[str]) -> None:
    """Dispatch: export entra <subcommand> ..."""
    if not args:
        console.print(_EXPORT_USAGE)
        return

    sub  = args[0].lower()
    rest = args[1:]
    opts = _parse_opts(rest)

    if sub in ("help", "--help", "-h", "?"):
        console.print(_EXPORT_USAGE)
    elif sub == "roadtools":
        _export_roadtools(state, opts)
    elif sub == "token":
        _export_token(state, opts)
    elif sub == "describe":
        _export_describe(state, opts)
    else:
        console.print(f"  [red]✗[/red] Unknown subcommand: {sub}")
        console.print(_EXPORT_USAGE)


def _export_roadtools(state: ShellState, opts: dict[str, str]) -> None:
    store = _active_entra_store(state)
    if store is None:
        _print_no_entra_cred_guidance(state, "export roadtools")
        return

    resource = opts.get("resource", _GRAPH)
    try:
        data = store.export_roadtools_auth(resource=resource)
    except ValueError as e:
        console.print(f"  [red]✗[/red] {e}")
        return

    out_path = Path(".roadtools_auth")
    out_path.write_text(json.dumps(data, indent=2))
    console.print(f"  [green]✓[/green] Written to {out_path.resolve()}")
    console.print("  Run: roadrecon gather --access-token $(cat .roadtools_auth | jq -r .accessToken)")


def _export_token(state: ShellState, opts: dict[str, str]) -> None:
    store = _active_entra_store(state)
    if store is None:
        _print_no_entra_cred_guidance(state, "export token")
        return

    resource = opts.get("resource", _GRAPH)
    tok = store.best_token(resource)
    if tok is None or tok.token_type != "access_token":
        console.print(
            f"  [red]✗[/red] No access token for {resource}. "
            "Run: acquire entra refresh --resource <res>"
        )
        return

    # soft_wrap: let the terminal visually wrap long tokens without Rich
    # inserting real newlines into the text — otherwise copy-pasting a
    # wrapped JWT reconstructs a broken, multi-line string.
    console.print(tok.value, soft_wrap=True)


def _export_describe(state: ShellState, opts: dict[str, str]) -> None:
    from quantum_mechanic.providers.entra.token_store import decode_jwt_claims

    store = _active_entra_store(state)
    if store is None:
        _print_no_entra_cred_guidance(state, "export describe")
        return

    resource = opts.get("resource", _GRAPH)
    tok = store.best_token(resource)
    if tok is None:
        console.print(f"  [red]✗[/red] No token available for {resource}.")
        return

    claims = tok.raw_claims or decode_jwt_claims(tok.value)
    if not claims:
        console.print("  [yellow]⚠[/yellow]  Token is opaque (not a JWT) — cannot decode claims.")
        return

    console.print(f"\n  [bold]Token claims — {resource}[/bold]")
    console.print(f"  [dim]Type: {tok.token_type}[/dim]")
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Claim", style="cyan")
    table.add_column("Value")

    priority = ["oid", "upn", "unique_name", "tid", "appid", "azp", "scp", "roles",
                "deviceid", "join_type", "amr", "exp", "iat", "nbf"]

    shown: set[str] = set()
    for key in priority:
        if key in claims:
            _add_claim_row(table, key, claims[key])
            shown.add(key)

    # Any remaining claims.
    for key, val in claims.items():
        if key not in shown and key not in ("aio", "rh", "uti", "ver"):
            _add_claim_row(table, key, val)

    if tok.expires_at:
        mins = tok.minutes_remaining
        expiry = tok.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        table.add_row("exp (readable)", f"{expiry}  ({mins:.0f} min remaining)" if mins else expiry)

    console.print(table)
    console.print()


# ================================================================
# Shared helpers
# ================================================================

def _apply_token_response(
    store: EntraTokenStore,
    resp: dict[str, Any],
    *,
    resource: str,
    client_id: str,
) -> None:
    """Unpack a token endpoint response dict into the store."""
    from quantum_mechanic.providers.entra.token_store import token_from_jwt

    if "error" in resp:
        err = resp.get("error_description", resp["error"])
        guidance = _cap_guidance(err)
        if guidance:
            console.print(guidance)
        else:
            console.print(f"  [red]✗[/red] Token exchange failed: {err}")
        return

    if "access_token" in resp:
        store.add_token(
            token_from_jwt(resp["access_token"], "access_token",
                           resource=resource, client_id=client_id)
        )

    if "refresh_token" in resp:
        from quantum_mechanic.providers.entra.ingest import ingest_refresh_token
        rt = ingest_refresh_token(
            resp["refresh_token"],
            tenant_id=store.tenant_id,
            client_id=client_id,
        )
        store.add_token(rt)

    if store.tenant_id is None and "access_token" in resp:
        from quantum_mechanic.providers.entra.token_store import decode_jwt_claims
        claims = decode_jwt_claims(resp["access_token"])
        store.tenant_id = claims.get("tid")
        if not store.user_upn:
            store.user_upn = claims.get("upn") or claims.get("unique_name")


def _store_from_response(
    resp: dict[str, Any],
    *,
    tenant_id: str,
    resource: str,
    client_id: str,
) -> EntraTokenStore:
    """Build a new EntraTokenStore from a token endpoint response."""
    store = EntraTokenStore(tenant_id=tenant_id)
    _apply_token_response(store, resp, resource=resource, client_id=client_id)
    return store


def _entra_friendly_name(store: EntraTokenStore) -> str:
    """Build a human-readable label from UPN and real tenant ID."""
    upn = store.user_upn
    tenant = store.tenant_id
    # Try to recover UPN and real tenant GUID from any access token JWT claims.
    try:
        from quantum_mechanic.providers.entra.token_store import decode_jwt_claims
        for tok in store.tokens:
            if tok.token_type == "access_token":
                claims = tok.raw_claims or decode_jwt_claims(tok.value)
                if not upn:
                    upn = claims.get("upn") or claims.get("unique_name")
                    if upn:
                        store.user_upn = upn
                tid = claims.get("tid")
                # Prefer a real GUID over the generic "common" endpoint.
                if tid and (not tenant or tenant == "common"):
                    tenant = tid
                    store.tenant_id = tid
                if upn and tid:
                    break
    except Exception:
        pass
    if upn:
        return upn
    if tenant and tenant != "common":
        return f"entra:{tenant[:8]}"  # short GUID prefix if no UPN available
    return "entra:unknown"


def _persist_store(state: ShellState, store: EntraTokenStore) -> int | None:
    """Upsert EntraTokenStore: update existing credential for same tenant+UPN, or create new."""
    if state.transport is None:
        console.print("  [red]✗[/red] No active workspace.")
        return None

    # _entra_friendly_name() corrects store.tenant_id from the "common"
    # placeholder to the real tenant GUID (decoded from token claims) as a
    # side effect — it MUST run before the store is serialized, or the
    # persisted secret_data keeps the uncorrected placeholder forever.
    friendly = _entra_friendly_name(store)
    secret = json.dumps({"token_store": store.to_dict()})

    # Check for an existing entra credential with the same identity to avoid duplicates.
    existing = state.transport.list_credentials(provider="entra")
    for cred in existing:
        if cred.get("friendly_name") == friendly:
            state.transport.update_credential(
                cred["id"], secret_data=secret, friendly_name=friendly
            )
            return cred["id"]

    cred_id: int = state.transport.add_credential(
        provider="entra",
        credential_type="token_store",
        secret_data=secret,
        friendly_name=friendly,
    )
    return cred_id


def _update_store(state: ShellState, store: EntraTokenStore) -> None:
    """Overwrite the active entra credential token data without changing the identity label."""
    if state.transport is None or state.active_credential_id is None:
        return
    secret = json.dumps({"token_store": store.to_dict()})
    state.transport.update_credential(state.active_credential_id, secret_data=secret)


def _mint_derived_cred(
    state: ShellState,
    store: EntraTokenStore,
    *,
    label_suffix: str,
    obtained_via: str,
    new_token_resource: str | None = None,
) -> int | None:
    """Create a NEW credential row derived from the currently active one.

    Used when an `acquire entra <resource>` action produces a token for a
    resource we don't already have — instead of overwriting the current
    cred's store, we mint a new cred so the operator can `use <old>` /
    `use <new>` to move between pivots.

    Args:
        store: The cloned/updated token store that will back the new cred.
        label_suffix: Appended to the parent's identity for the new cred's
                      friendly name, e.g. "→ ARM" or "→ Graph +User.Read.All".
        obtained_via: Free-form marker recorded on the credential row for
                      audit purposes (e.g. "acquire entra arm").
        new_token_resource: If set, expires_at is taken from the AT for that
                            resource on the store; otherwise None (never
                            expires from the cred-list perspective).

    Returns:
        The new credential id, or None if the workspace isn't ready.
    """
    if state.workspace is None or state.active_credential_id is None:
        return None
    parent_id = state.active_credential_id
    parent_name = state.active_credential_label or _entra_friendly_name(store)
    new_name = f"{parent_name} {label_suffix}"
    expires_at = None
    if new_token_resource:
        tok = store.best_token(new_token_resource)
        if tok and tok.expires_at:
            expires_at = tok.expires_at.isoformat()

    secret = json.dumps({"token_store": store.to_dict()})
    new_id = state.workspace.add_credential(
        provider="entra",
        credential_type="token_store",
        secret_data=secret,
        friendly_name=new_name,
        derived_from_id=parent_id,
        expires_at=expires_at,
        obtained_via=obtained_via,
    )
    state.active_credential_id = new_id
    state.active_credential_label = new_name
    return new_id


def _set_active(state: ShellState, cred_id: int, store: EntraTokenStore) -> None:
    """Set the new credential as the active one."""
    state.active_credential_id = cred_id
    state.active_credential_label = _entra_friendly_name(store)


def _active_entra_store(state: ShellState) -> EntraTokenStore | None:
    """Return the active EntraTokenStore from the workspace, or None."""
    if state.workspace is None or state.active_credential_id is None:
        return None

    from quantum_mechanic.providers.entra.auth import EntraAuthProvider

    cred = state.workspace.get_credential(state.active_credential_id)
    if cred is None or cred.provider != "entra":
        return None

    raw = state.workspace.get_credential_secret(state.active_credential_id)
    secret = json.loads(raw)
    provider = EntraAuthProvider()
    return provider.authenticate(secret)


def _print_no_entra_cred_guidance(state: ShellState, action: str) -> None:
    """Print a specific guidance message when `acquire entra <action>` is invoked
    but the active cred is either absent, on the wrong provider, or a captured
    Azure token with no refresh material.

    Beats the old generic "No active entra credential" that left operators
    guessing which subcommand to run next.
    """
    # No workspace / no active cred at all.
    if state.workspace is None or state.active_credential_id is None:
        console.print(
            "  [red]✗[/red] No active credential. First get one via one of:\n"
            "    • [cyan]acquire entra device_code[/cyan]   "
            "[dim](phone-verify, no local az session needed)[/dim]\n"
            "    • [cyan]acquire entra interactive[/cyan]   "
            "[dim](browser OAuth, works through Conditional Access)[/dim]\n"
            "    • [cyan]acquire entra ropc[/cyan] --username <upn> --password <p> --tenant <t>\n"
            "    • [cyan]import entra <format>[/cyan]       "
            "[dim](for existing dumps/cookies/JWTs — see `import entra`)[/dim]"
        )
        return

    cred = state.workspace.get_credential(state.active_credential_id)
    if cred is None:
        console.print("  [red]✗[/red] Active credential no longer exists.")
        return

    if cred.provider == "entra":
        # Cred is Entra but store somehow couldn't authenticate — surface the
        # generic message so we don't hide a real error behind guidance.
        console.print(
            f"  [red]✗[/red] Active entra credential #{cred.id} could not be "
            f"loaded. Try `raw {cred.id}` to inspect it or re-import."
        )
        return

    # Wrong provider — the specific case that motivated this fix.
    if cred.provider == "azure" and cred.credential_type == "captured_token":
        console.print(
            f"  [red]✗[/red] Cannot `acquire entra {action}` from cred "
            f"[bold]#{cred.id}[/bold] — it's a captured Azure ARM token with no "
            "refresh material. Captured tokens are audience-bound snapshots "
            "and cannot be exchanged for a Graph token.\n"
            "  To pivot to Graph, get an RT-backed session:\n"
            "    → [cyan]acquire entra device_code[/cyan]   "
            "[dim](or interactive / ropc)[/dim]\n"
            "  Then FOCI expansion works: `acquire entra refresh --resource "
            "https://graph.microsoft.com`."
        )
        return

    if cred.provider == "azure":
        console.print(
            f"  [red]✗[/red] Cannot `acquire entra {action}` from cred "
            f"[bold]#{cred.id}[/bold] (azure/{cred.credential_type}). Azure "
            "and Entra live in the same Microsoft ecosystem but this "
            "command needs an Entra store with a refresh token.\n"
            "  Get one via [cyan]acquire entra device_code[/cyan] / "
            "[cyan]interactive[/cyan] / [cyan]ropc[/cyan]."
        )
        return

    console.print(
        f"  [red]✗[/red] Active cred [bold]#{cred.id}[/bold] is {cred.provider.upper()} "
        f"({cred.credential_type}). `acquire entra {action}` needs an entra "
        "credential.\n"
        "  Get one with [cyan]acquire entra device_code[/cyan] / "
        "[cyan]interactive[/cyan] / [cyan]ropc[/cyan]."
    )


def _cap_guidance(error_text: str) -> str | None:
    from quantum_mechanic.providers.entra.token_store import EntraTokenStore
    return EntraTokenStore.cap_guidance(error_text)


def _print_import_summary(store: EntraTokenStore, cred_id: int) -> None:
    """Display the post-import summary table."""

    console.print()
    console.print(f"  [bold][entra][/bold] Credential #{cred_id} imported")
    console.print()

    if store.tenant_id:
        console.print(f"  Tenant:        {store.tenant_id}")
    if store.user_upn:
        console.print(f"  User:          {store.user_upn}")

    cap_str = "YES — device claim token present" if store.has_device_claims() else "NO"
    if store.device:
        cap_str = f"YES — virtual device enrolled ({store.device.join_type})"
    console.print(f"  Device claims: {cap_str}")

    if store.has_device_claims() and not store.device:
        console.print(
            "  [yellow]CAP status:[/yellow]  Joined Device may be satisfied. "
            "Compliant Device: unknown."
        )

    console.print()

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Token")
    table.add_column("Expires")
    table.add_column("Resource")

    for tok in store.tokens:
        exp_str = "—"
        if tok.expires_at:
            mins = tok.minutes_remaining
            exp_str = tok.expires_at.strftime("%Y-%m-%d %H:%M UTC")
            if mins is not None and mins < 60:
                exp_str += f"  ({mins:.0f}m remaining)"
        res = tok.resource or ("FOCI — 7 resources" if tok.foci else "—")
        table.add_row(tok.token_type, exp_str, res)

    console.print(table)
    console.print()
    console.print(
        "  [green]✓[/green] Active provider set to entra. "
        "Run: [cyan]run discovery/entra_whoami[/cyan]"
    )
    console.print()


def _add_claim_row(table: Table, key: str, value: Any) -> None:
    """Format a JWT claim for the describe table."""
    from datetime import datetime
    if key in ("exp", "iat", "nbf") and isinstance(value, int):
        try:
            dt = datetime.fromtimestamp(value, tz=UTC)
            display = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            display = str(value)
    elif isinstance(value, list):
        display = ", ".join(str(v) for v in value)
    else:
        display = str(value)
    table.add_row(key, display)


def _parse_opts(args: list[str]) -> dict[str, str]:
    """Parse --key value pairs from an arg list."""
    opts: dict[str, str] = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            key = args[i][2:]
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                opts[key] = args[i + 1]
                i += 2
            else:
                opts[key] = "true"
                i += 1
        else:
            i += 1
    return opts


# Inline import to avoid circular at module level.
from quantum_mechanic.providers.entra.token_store import EntraTokenStore  # noqa: E402
