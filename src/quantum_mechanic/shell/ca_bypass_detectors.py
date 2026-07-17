# ================================================================
# MODULE: quantum_mechanic.shell.ca_bypass_detectors
# ----------------------------------------------------------------
# PURPOSE:   Rule engine that walks enumerated Entra Conditional
#            Access policies and flags bypass opportunities. Feeds
#            the `check-ca-bypasses` shell command.
#
# INPUTS:    List of policy dicts as emitted by
#            discovery/entra_enum_conditional_access_policies.
#
# OUTPUTS:   list[BypassFinding] sorted by caller; each finding
#            carries severity, title, description, affected policy
#            names, and remediation guidance.
#
# DESIGN:    Each detector is a top-level function taking the
#            filtered list of enabled policies (except
#            detect_report_only_stale which needs all policies) and
#            returning findings independently. run_all_detectors
#            fans out and concatenates.
# ================================================================

from typing import Any

from quantum_mechanic.providers.entra.foci import FOCI_CLIENT_IDS
from quantum_mechanic.techniques.discovery.entra_enum_conditional_access_policies import (
    get_list,
    get_list_from_policy,
)


class BypassFinding:
    """One CA-policy bypass opportunity surfaced by a detector."""

    def __init__(
        self,
        severity: str,
        title: str,
        description: str,
        affected_policies: list[str],
        remediation: str,
    ) -> None:
        self.severity = severity
        self.title = title
        self.description = description
        self.affected_policies = affected_policies
        self.remediation = remediation

def run_all_detectors(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    all_findings = []
    all_findings.extend(detect_legacy_auth_allowed(enabled_policies))
    all_findings.extend(detect_device_code_not_blocked(enabled_policies))
    all_findings.extend(detect_foci_exclusion_blast(enabled_policies))
    all_findings.extend(detect_break_glass_over_exclusion(enabled_policies))
    all_findings.extend(detect_grant_or_weakness(enabled_policies))
    all_findings.extend(detect_weak_mfa_strength(enabled_policies))
    all_findings.extend(detect_platform_gaps(enabled_policies))
    all_findings.extend(detect_no_workload_ca(enabled_policies))
    all_findings.extend(detect_guest_coverage_gap(enabled_policies))
    all_findings.extend(detect_session_hijack_risk(enabled_policies))
    all_findings.extend(detect_no_token_protection(enabled_policies))
    all_findings.extend(detect_auth_transfer_gap(enabled_policies))
    all_findings.extend(detect_report_only_stale(policies)) # Needs all policies
    all_findings.extend(detect_location_trust_risk(enabled_policies))
    return all_findings

def detect_legacy_auth_allowed(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        clients = [x.lower() for x in get_list(p.get("client_app_types"))]
        controls = [x.lower() for x in get_list(p.get("grant_controls"))]
        if ("exchangeactivesync" in clients or "other" in clients or "all" in clients) and "block" not in controls:
            findings.append(BypassFinding(
                severity="CRITICAL",
                title="Legacy Authentication Allowed",
                description="Policy permits legacy auth (ExchangeActiveSync or Other) without blocking, which bypasses modern MFA.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Block legacy authentication or transition to modern authentication."
            ))
    return findings

def detect_device_code_not_blocked(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    blocked = False
    for p in policies:
        flows = p.get("auth_flows", "").lower()
        controls = [x.lower() for x in get_list(p.get("grant_controls"))]
        if "devicecodeflow" in flows and "block" in controls:
            blocked = True
            break
    if not blocked and policies:
        return [BypassFinding(
            severity="HIGH",
            title="Device Code Flow Not Blocked",
            description="No policy explicitly blocks the Device Code Flow, making the tenant vulnerable to phishing via device code.",
            affected_policies=[],
            remediation="Create a policy that targets 'All Users' and blocks the 'deviceCodeFlow' authentication transfer method."
        )]
    return []

def detect_foci_exclusion_blast(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    """Flag policies that exclude any FOCI-family app.

    Any FOCI app exclusion is a blast-radius bug: a token issued for the
    excluded client can be exchanged for a token on ANY other FOCI-family
    client, so the exclusion covers the entire family (Office, Teams,
    OneDrive, Outlook Mobile, Office Web, Office 365 Management,
    O365 Shell Mobile — see providers/entra/foci.py::FOCI_CLIENT_IDS for the
    authoritative list).
    """
    findings = []
    for p in policies:
        exc_apps = get_list_from_policy(p, "excluded_apps")
        overlap = [a for a in exc_apps if a in FOCI_CLIENT_IDS]
        if overlap:
            labeled = [f"{a} ({FOCI_CLIENT_IDS[a]})" for a in overlap]
            findings.append(BypassFinding(
                severity="HIGH",
                title="FOCI Application Exclusion",
                description=(
                    f"Policy excludes an app in a FOCI family ({', '.join(labeled)}). "
                    "A token issued for this app can be exchanged for any other "
                    "app in the family, so the exclusion effectively covers all "
                    f"{len(FOCI_CLIENT_IDS)} known FOCI clients."
                ),
                affected_policies=[p.get("display_name", "Untitled")],
                remediation=(
                    "Do not exclude FOCI family apps from MFA. Use Conditional "
                    "Access Authentication Context instead."
                ),
            ))
    return findings

def detect_break_glass_over_exclusion(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    if not policies:
        return []
    
    exclusion_counts = {}
    for p in policies:
        for u in get_list(p.get("excluded_users")):
            exclusion_counts[u] = exclusion_counts.get(u, 0) + 1
            
    total_enabled = len(policies)
    over_excluded = [u for u, count in exclusion_counts.items() if count == total_enabled and u != "None"]
    
    if over_excluded:
        return [BypassFinding(
            severity="HIGH",
            title="Account Excluded from All Policies",
            description=f"Users ({', '.join(over_excluded)}) are excluded from ALL enabled CA policies. If these are not tightly monitored Break Glass accounts, this is a massive risk.",
            affected_policies=["All Enabled Policies"],
            remediation="Ensure these are Break Glass accounts. Monitor all sign-ins for these accounts heavily."
        )]
    return []

def detect_grant_or_weakness(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        grant_op = str(p.get("grant_operator", "OR")).upper()
        controls = [x.lower() for x in get_list(p.get("grant_controls"))]
        
        if grant_op == "OR" and len(controls) > 1:
            mfa_present = any("mfa" in c or "authstrength" in c for c in controls)
            if mfa_present:
                weak_controls = [c for c in controls if "mfa" not in c and "authstrength" not in c]
                if weak_controls:
                    findings.append(BypassFinding(
                        severity="HIGH",
                        title="Vulnerable 'OR' Grant Operator",
                        description=f"Policy requires MFA but uses 'OR' with weaker controls ({', '.join(weak_controls)}). An attacker might satisfy the weaker control to bypass MFA entirely.",
                        affected_policies=[p.get("display_name", "Untitled")],
                        remediation="Change the grant control to 'Require all the selected controls' (AND)."
                    ))
    return findings

def detect_weak_mfa_strength(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        controls = [x.lower() for x in get_list(p.get("grant_controls"))]
        if "mfa" in controls and not any("authstrength" in c for c in controls):
            findings.append(BypassFinding(
                severity="MEDIUM",
                title="Generic MFA Used Instead of Phishing-Resistant",
                description="Policy uses the generic 'Require MFA' control rather than a specific phishing-resistant Authentication Strength.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Upgrade the grant control to 'Require authentication strength' and select a phishing-resistant strength."
            ))
    return findings

def detect_platform_gaps(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        inc_p = get_list(p.get("included_platforms"))
        if inc_p and "All" not in inc_p:
            findings.append(BypassFinding(
                severity="MEDIUM",
                title="Platform Exclusions Enable User-Agent Spoofing",
                description=f"Policy only targets specific platforms ({', '.join(inc_p)}). An attacker can bypass this policy by simply spoofing their User-Agent.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Target 'Any device' (All) in the device platforms condition."
            ))
    return findings

def detect_no_workload_ca(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    # Very rudimentary check: Does any policy target SPs?
    sp_policies = False
    for p in policies:
        # In the payload, SP risk levels or specific workload identity settings would indicate SP targeting
        if p.get("sp_risk_levels") and p.get("sp_risk_levels") != "None":
            sp_policies = True
            break
            
    if not sp_policies and policies:
        return [BypassFinding(
            severity="MEDIUM",
            title="No Workload Identity Protection",
            description="No Conditional Access policies appear to target Service Principals. Workload identities are completely unprotected by CA.",
            affected_policies=[],
            remediation="Create Conditional Access policies targeting Workload Identities based on Service Principal Risk."
        )]
    return []

def detect_guest_coverage_gap(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        inc_u = get_list(p.get("included_users"))
        exc_g = p.get("exclude_guest_types")
        if "All" in inc_u and exc_g and exc_g != "None":
            findings.append(BypassFinding(
                severity="MEDIUM",
                title="Guest Coverage Gap",
                description=f"Policy targets 'All Users' but explicitly excludes guest types ({exc_g}). Ensure these guests are covered by another policy.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Ensure a dedicated fallback policy covers guest/external users with appropriate restrictions."
            ))
    return findings

def detect_session_hijack_risk(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        pb = p.get("session_persistent_browser", "").lower()
        tp = str(p.get("session_token_protection", "")).lower()
        if pb == "always" and tp != "true":
            findings.append(BypassFinding(
                severity="MEDIUM",
                title="Session Hijack Risk (Persistent Browser)",
                description="Policy explicitly configures 'Persistent Browser: always' without Token Protection. Stolen session cookies will not expire across browser restarts.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Set persistent browser session to 'Never' or enable Token Protection."
            ))
    return findings

def detect_no_token_protection(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    tp_enabled = any(str(p.get("session_token_protection", "")).lower() == "true" for p in policies)
    if not tp_enabled and policies:
        return [BypassFinding(
            severity="MEDIUM",
            title="Token Protection Not Enabled",
            description="No enabled policy enforces Token Protection (Secure Sign-In Session), making all sessions vulnerable to token theft/AiTM.",
            affected_policies=[],
            remediation="Enable Token Protection in session controls for high-risk users and apps."
        )]
    return []

def detect_auth_transfer_gap(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    blocked = False
    for p in policies:
        flows = p.get("auth_flows", "").lower()
        controls = [x.lower() for x in get_list(p.get("grant_controls"))]
        if "authenticationtransfer" in flows and "block" in controls:
            blocked = True
            break
    if not blocked and policies:
        return [BypassFinding(
            severity="LOW",
            title="Authentication Transfer Not Blocked",
            description="No policy explicitly blocks the Authentication Transfer flow.",
            affected_policies=[],
            remediation="Create a policy to block 'authenticationTransfer' flow."
        )]
    return []

def detect_report_only_stale(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    findings = []
    for p in policies:
        state = p.get("state", "").lower()
        if "report" in state:
            findings.append(BypassFinding(
                severity="INFO",
                title="Policy in Report-Only Mode",
                description="Policy is in Report-Only mode and does not enforce its controls.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Review sign-in logs and switch the policy to 'Enabled'."
            ))
    return findings

def detect_location_trust_risk(policies: list[dict[str, Any]]) -> list[BypassFinding]:
    """Flag policies that exclude 'AllTrusted' locations.

    Uses the structured _list accessor so multi-CIDR named locations
    (e.g. "SOC IPs (10.0.0.1/32, 10.0.0.2/32)") aren't split on the
    interior comma — see B3 in the v1.0-rc0 release notes.
    """
    findings = []
    for p in policies:
        exc_loc = get_list_from_policy(p, "excluded_locations")
        if "AllTrusted" in exc_loc:
            findings.append(BypassFinding(
                severity="INFO",
                title="All Trusted Locations Excluded",
                description="Policy excludes 'All Trusted Locations'. If any broad network (like a VPN IP pool or large corporate subnet) is marked trusted, an attacker inside that network bypasses MFA.",
                affected_policies=[p.get("display_name", "Untitled")],
                remediation="Audit named locations. Avoid excluding trusted networks from critical policies."
            ))
    return findings
