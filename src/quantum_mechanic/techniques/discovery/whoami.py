# ================================================================
# TECHNIQUE: discovery/whoami
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1087 — Account Discovery
#
# PURPOSE:   Identify the principal associated with the current
#            credentials. The most basic operation in any cloud
#            assessment — "who am I and what account am I in?"
#
# PROVIDERS: AWS, Azure, GCP, OCI
#
# HOW IT WORKS:
#   AWS   — Calls sts:GetCallerIdentity. Returns ARN, account
#           ID, and user ID. The ARN encodes principal type
#           (user, role, assumed-role, federated-user, root).
#   Azure — Acquires a management token, decodes the JWT claims
#           to extract object ID, tenant ID, and UPN/app ID.
#           Then enumerates accessible subscriptions.
#   GCP   — For service accounts, reads email and project from
#           the credential object. For user creds, calls the
#           OAuth2 tokeninfo endpoint.
#   OCI   — Calls Identity.GetUser() with the user OCID from
#           the config, then GetTenancy() for tenancy details.
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: sts:GetCallerIdentity
#           This is a benign, non-privileged call. However,
#           GetCallerIdentity from an unexpected source IP or
#           user agent is a strong indicator of credential theft.
#           Alert on: GetCallerIdentity from IPs outside your
#           corporate CIDR ranges.
#
#   Azure — Azure AD Sign-in Logs: Token acquisition events.
#           Look for sign-ins from unexpected IPs, devices, or
#           with unusual user agent strings.
#
#   GCP   — Cloud Audit Logs: tokeninfo calls. Monitor for token
#           acquisitions from unexpected IPs or service accounts.
#
#   OCI   — Audit Service: GetUser, GetTenancy calls. Monitor
#           for API key usage from unexpected source IPs.
#
# SAFE:     Yes — completely read-only, no state changes.
# ================================================================

from __future__ import annotations

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique
from quantum_mechanic.providers.base import WhoAmIResult


@technique(
    technique_id="discovery/whoami",
    tactic="Discovery",
    mitre_id="T1087.004",
    providers=["aws", "azure", "gcp", "oci"],
    severity="info",
    safe=True,
    description="Identify the active principal associated with the current credentials.",
)
def execute(ctx: ExecutionContext) -> WhoAmIResult:
    """Execute the whoami technique.

    Calls the provider's whoami method through the execution
    context, which handles API logging and principal storage
    automatically.

    Args:
        ctx: Execution context with active credential and provider.

    Returns:
        WhoAmIResult with normalized identity information.
    """
    # ================================================================
    # The ctx.whoami() call does all the heavy lifting:
    #   1. Calls provider.whoami(session) for the active provider
    #   2. Logs the API call in the workspace api_log
    #   3. Stores the discovered principal in the principals table
    #   4. Links the credential to the principal
    #   5. Stores the account in the accounts table
    #
    # The technique function itself is intentionally simple — the
    # complexity lives in the harness, not in the technique code.
    # This is by design: technique authors should focus on security
    # logic, not infrastructure plumbing.
    # ================================================================
    result = ctx.whoami()
    return result
