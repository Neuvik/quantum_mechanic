# ================================================================
# TECHNIQUE: discovery/gcp_enum_api_key
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1528 — Steal Application Access Token
#
# PURPOSE:   Audit a discovered Google API key for over-privileged
#            access across 40+ Google Cloud services.
#
# PROVIDERS: GCP
#
# HOW IT WORKS:
#   1. Probes multiple Google API endpoints in parallel using the key.
#   2. Implements specialized logic for Firebase (where 400 Bad
#      Request can indicate a valid key but invalid parameters).
#   3. Categorizes accessible APIs by Risk Level (CRITICAL, HIGH, etc.).
#
# OPSEC:     LOW — Keys are meant for client-side use; probes look
#            like legitimate application traffic.
# SAFE:      Yes
# ================================================================

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, ParameterType, technique

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------
# Probe Definitions
# ----------------------------------------------------------------

PROBES = [
    # --- CRITICAL RISK ---
    {
        "service": "Gemini AI (Models)",
        "url": "https://generativelanguage.googleapis.com/v1beta/models?key={key}",
        "method": "GET",
        "risk": "CRITICAL",
        "hint": "Full access to Gemini LLM infrastructure. High billing risk.",
    },
    {
        "service": "Gemini AI (Files)",
        "url": "https://generativelanguage.googleapis.com/v1beta/files?key={key}",
        "method": "GET",
        "risk": "CRITICAL",
        "hint": "Access to cached files and training data stored in Gemini.",
    },
    {
        "service": "Cloud Vision",
        "url": "https://vision.googleapis.com/v1/images:annotate?key={key}",
        "method": "POST",
        "payload": {
            "requests": [
                {
                    "image": {"source": {"imageUri": "https://example.com/test.jpg"}},
                    "features": [{"type": "LABEL_DETECTION"}],
                }
            ]
        },
        "risk": "CRITICAL",
        "hint": "Ability to run expensive image analysis. High billing risk.",
    },
    # --- HIGH RISK ---
    {
        "service": "Firebase Auth (Sign Up)",
        "url": "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={key}",
        "method": "POST",
        "payload": {"email": "test@example.com", "password": "password"},
        "risk": "HIGH",
        "success_msg": ["INVALID_EMAIL", "EMAIL_EXISTS", "OPERATION_NOT_ALLOWED"],
        "hint": "Manage users and identities in Firebase applications.",
    },
    {
        "service": "Firebase Cloud Messaging",
        "url": "https://fcm.googleapis.com/fcm/send?key={key}",
        "method": "POST",
        "payload": {"registration_ids": ["ABC"]},
        "risk": "HIGH",
        "success_msg": ["InvalidRegistration"],  # 400 with this message means key is valid
        "hint": "Send push notifications to all app users.",
    },
    {
        "service": "Google Cloud Storage (List)",
        "url": "https://storage.googleapis.com/storage/v1/b?project=test&key={key}",
        "method": "GET",
        "risk": "HIGH",
        "hint": "If status 403 (Forbidden) vs 400 (Bad Project), access level varies.",
    },
    # --- MEDIUM RISK ---
    {
        "service": "Cloud Translation",
        "url": "https://translation.googleapis.com/language/translate/v2?key={key}&q=hello&target=es",
        "method": "GET",
        "risk": "MEDIUM",
        "hint": "Incurs costs for text translation.",
    },
    {
        "service": "YouTube Data API",
        "url": "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true&key={key}",
        "method": "GET",
        "risk": "MEDIUM",
        "hint": "Access to YouTube account data.",
    },
    # --- LOW RISK ---
    {
        "service": "Static Maps",
        "url": "https://maps.googleapis.com/maps/api/staticmap?center=40,73&size=400x400&key={key}",
        "method": "GET",
        "risk": "LOW",
        "hint": "Standard client-side map usage.",
    },
    {
        "service": "Places Search",
        "url": "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33,151&radius=1500&key={key}",
        "method": "GET",
        "risk": "LOW",
        "hint": "Location search access.",
    },
]

# ----------------------------------------------------------------
# Loot & Formatter
# ----------------------------------------------------------------

LOOT_SCHEMA = [
    ("service", "Service", "bold white"),
    ("risk", "Risk", "bold yellow"),
    ("details", "Details", "dim"),
]


def format_gcp_api_audit(result: Any) -> None:
    """Formatter for GCP API Key Audit results."""
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    findings = data.get("findings", [])

    if not findings:
        console.print("  [bold red]✗[/bold red] No accessible services found for this API key.")
        return

    console.print(
        f"  [bold green]✓[/bold green] Discovered [bold cyan]{len(findings)}[/bold cyan] Accessible Service(s)"
    )

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Service", style="bold white")
    tbl.add_column("Risk Level")
    tbl.add_column("Description", style="dim")

    # Order by risk severity
    severity = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: severity.get(x["risk"], 99)):
        risk_style = (
            "bold red"
            if f["risk"] == "CRITICAL"
            else ("bold yellow" if f["risk"] == "HIGH" else "white")
        )
        tbl.add_row(f["service"], f"[{risk_style}]{f['risk']}[/{risk_style}]", f["hint"])

    console.print(tbl)


@technique(
    technique_id="discovery/gcp_enum_api_key",
    tactic="discovery",
    mitre_id="T1528",
    providers=[],  # Unauthenticated (uses raw key)
    severity="high",
    safe=True,
    description="Audit a Google API key for access across Gemini, Firebase, Storage, and more.",
    formatter=format_gcp_api_audit,
    loot_schema=LOOT_SCHEMA,
    loot_items_key="findings",
    parameters=[
        Parameter(
            "api_key",
            "The raw Google API key to audit (starts with AIza).",
            required=True,
            type=ParameterType.STRING,
            example="AIzaSyA...",
        ),
        Parameter(
            "threads",
            "Parallel threads for probing.",
            required=False,
            type=ParameterType.INTEGER,
            default=10,
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute GCP API Key Audit."""
    api_key = ctx.get_param("api_key")
    threads = int(ctx.get_param("threads", 10))
    findings = []
    attempts = []

    ctx.info(f"Auditing API key: {api_key[:8]}... against {len(PROBES)} services")

    def run_probe(probe: dict) -> None:
        url = probe["url"].format(key=api_key)
        method = probe["method"]
        payload = probe.get("payload")

        try:
            with httpx.Client(timeout=10.0) as client:
                if method == "GET":
                    resp = client.get(url)
                else:
                    resp = client.post(url, json=payload)

                accessible = False

                # Success Logic 1: Standard HTTP Success
                if resp.status_code in (200, 201, 204, 429):
                    accessible = True

                # Success Logic 2: Specific JSON error codes (Firebase/FCM logic)
                elif "success_msg" in probe:
                    body = resp.text
                    if any(msg in body for msg in probe["success_msg"]):
                        accessible = True

                status_label = f"[{resp.status_code}]"
                if accessible:
                    ctx.success(f"Accessible: {probe['service']} {status_label}")
                    findings.append(
                        {"service": probe["service"], "risk": probe["risk"], "hint": probe["hint"]}
                    )
                else:
                    # Log failure to activity log (but hidden from main shell)
                    ctx.debug(f"Denied: {probe['service']} {status_label}")

                attempts.append(
                    {
                        "service": probe["service"],
                        "status_code": resp.status_code,
                        "accessible": accessible,
                    }
                )

        except Exception as e:
            msg = f"Failed to probe {probe['service']}: {e}"
            ctx.debug(msg)
            logger.debug(msg)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(run_probe, PROBES)

    return {
        "status": "success",
        "api_key_prefix": api_key[:8],
        "findings": findings,
        "total_probes": len(PROBES),
        "probes_run": len(attempts),
    }
