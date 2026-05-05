# ================================================================
# MODULE: quantum_mechanic.agent.summarizer
# ----------------------------------------------------------------
# PURPOSE:   Converts full TechniqueResult data into a compact,
#            token-efficient summary for agent mode output.
#
# DESIGN:    Agent mode never outputs raw data dicts — too many
#            tokens. Instead, summarize() extracts:
#              - A one-line human-readable summary string
#              - A list of risk_flags (strings, agent acts on these)
#              - A minimal stat block
#
#            Each technique registers a custom summarizer. If none
#            exists, a generic fallback is used.
#
#            For the full data, the agent reads the workspace
#            database or the markdown note written to disk.
# ================================================================

from __future__ import annotations

from typing import Any

# ================================================================
# Summary result — what agent mode outputs instead of raw data.
# ================================================================

class AgentSummary:
    """Compact output for agent mode consumption."""

    def __init__(
        self,
        *,
        technique: str,
        tactic: str,
        provider: str,
        ok: bool,
        summary: str,
        risk_flags: list[str],
        stats: dict[str, Any],
        ms: int,
        api_calls: int,
        error: str | None = None,
    ) -> None:
        self.technique = technique
        self.tactic = tactic
        self.provider = provider
        self.ok = ok
        self.summary = summary
        self.risk_flags = risk_flags
        self.stats = stats
        self.ms = ms
        self.api_calls = api_calls
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        """Compact dict — no indent, minimal keys."""
        d: dict[str, Any] = {
            "ok": self.ok,
            "technique": self.technique,
            "tactic": self.tactic,
            "provider": self.provider,
            "summary": self.summary,
        }
        if self.risk_flags:
            d["risk_flags"] = self.risk_flags
        if self.stats:
            d["stats"] = self.stats
        d["ms"] = self.ms
        d["api_calls"] = self.api_calls
        if self.error:
            d["error"] = self.error
        return d


# ================================================================
# Per-technique summarizers.
# Each function receives the raw data dict and returns
# (summary: str, risk_flags: list[str], stats: dict)
# ================================================================

def _summarize_whoami(data: dict, provider: str) -> tuple[str, list[str], dict]:
    name = data.get("friendly_name", "unknown")
    ptype = data.get("principal_type", "unknown")
    account = data.get("account_id", "?")
    summary = f"{ptype} '{name}' in account {account}"
    return summary, [], {"principal_type": ptype, "account": account}


def _summarize_enum_iam(data: dict, provider: str) -> tuple[str, list[str], dict]:
    flags: list[str] = []
    stats: dict[str, Any] = {}

    if provider == "aws":
        attached = data.get("attached_policies", [])
        inline = data.get("inline_policies", [])
        policy_names = [p.get("PolicyName", "") for p in attached]
        stats = {"attached_policies": len(attached), "inline_policies": len(inline)}

        # Risk detection — actions that can lead to privilege escalation
        _RISKY_POLICIES = {
            "AdministratorAccess",
            "PowerUserAccess",
            "IAMFullAccess",
        }
        _RISKY_TERMS = [
            "iam:PassRole",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:CreatePolicyVersion",
        ]
        for name in policy_names:
            if name in _RISKY_POLICIES:
                flags.append(f"policy:{name}")

        # Check inline policy statements for risky actions
        for p in inline:
            for stmt in p.get("statements", []):
                for term in _RISKY_TERMS:
                    if term.lower() in str(stmt).lower() and term not in flags:
                        flags.append(term)

        principal = data.get("principal", "unknown")
        count = len(attached) + len(inline)
        summary = f"{principal} has {count} polic{'ies' if count != 1 else 'y'}."
        if flags:
            summary += f" Flags: {', '.join(flags)}."

    elif provider == "azure":
        assignments = data.get("role_assignments", [])
        roles = [a.get("roleName", "") for a in assignments]
        stats = {"role_assignments": len(assignments)}
        _RISKY_AZURE = {"Owner", "Contributor", "User Access Administrator"}
        for role in roles:
            if role in _RISKY_AZURE:
                flags.append(f"role:{role}")
        principal = data.get("principal", "unknown")
        summary = f"{principal} has {len(assignments)} role assignment(s)."
        if flags:
            summary += f" Flags: {', '.join(flags)}."

    elif provider == "gcp":
        roles = data.get("project_roles", [])
        stats = {"project_roles": len(roles)}
        _RISKY_GCP = {"roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"}
        for r in roles:
            role_id = r.get("role", "")
            if role_id in _RISKY_GCP:
                flags.append(f"role:{role_id}")
        principal = data.get("principal", "unknown")
        summary = f"{principal} has {len(roles)} project role(s)."
        if flags:
            summary += f" Flags: {', '.join(flags)}."

    elif provider == "oci":
        groups = data.get("groups", [])
        policies = data.get("policies", [])
        stats = {"groups": len(groups), "policies": len(policies)}
        _RISKY_GROUPS = {"Administrators"}
        for g in groups:
            if g.get("name") in _RISKY_GROUPS:
                flags.append(f"group:{g.get('name')}")
        principal = data.get("principal", "unknown")
        summary = f"{principal} in {len(groups)} group(s), {len(policies)} polic{'ies' if len(policies) != 1 else 'y'} discovered across compartments."
        if flags:
            summary += f" Flags: {', '.join(flags)}."

    else:
        summary = "IAM enumeration complete."

    return summary, flags, stats


def _summarize_enum_compute(data: dict, provider: str) -> tuple[str, list[str], dict]:
    instances = data.get("instances", [])
    total = data.get("total", len(instances))
    flags: list[str] = []

    # Count instances with attached identities
    with_identity = [i for i in instances if i.get("instance_profile_arn") or i.get("identity")]
    high_value = []

    for inst in with_identity:
        note = inst.get("risk_note", "")
        if note:
            flags.append(note)
        ident = inst.get("instance_profile_arn") or inst.get("identity") or ""
        iid = inst.get("instance_id") or inst.get("id") or "unknown"
        if ident:
            high_value.append(f"{iid} ({ident.split('/')[-1]})")

    stats: dict[str, Any] = {
        "total_instances": total,
        "with_identity": len(with_identity),
    }
    if high_value:
        stats["high_value_targets"] = high_value[:5]  # cap at 5 to stay compact

    summary = f"{total} instance(s). {len(with_identity)} with attached identit{'ies' if len(with_identity) != 1 else 'y'}."
    if high_value:
        summary += f" High-value: {', '.join(high_value[:3])}{'...' if len(high_value) > 3 else ''}."

    return summary, flags, stats

def _summarize_assume_role_chain(data: dict, provider: str) -> tuple[str, list[str], dict]:
    chains = data.get("chains", [])
    assumed = [c for c in chains if c.get("assumed")]
    failed = [c for c in chains if not c.get("assumed") and not c.get("safe_mode")]
    dry_run = data.get("safe_mode", False)

    flags: list[str] = []
    if assumed:
        max_depth = max(c.get("depth", 0) for c in assumed)
        flags.append(f"role_chain_depth:{max_depth + 1}")
        for c in assumed:
            role_name = c.get("role_arn", "").split("/")[-1]
            flags.append(f"assumed:{role_name}")

    stats: dict[str, Any] = {
        "total_chains": len(chains),
        "assumed": len(assumed),
        "failed": len(failed),
        "safe_mode": dry_run,
    }

    start = data.get("starting_principal", "unknown").split("/")[-1]
    if dry_run:
        summary = f"{start} can assume {len(chains)} role(s) (safe_mode — not executed)."
    elif assumed:
        summary = (
            f"{start} pivoted through {len(assumed)} role(s). "
            f"Derived credentials stored. Max depth: {max(c.get('depth',0) for c in assumed)+1}."
        )
    else:
        summary = f"{start} — no assumable roles found."

    return summary, flags, stats


def _summarize_vm_execute_command(data: dict, provider: str) -> tuple[str, list[str], dict]:
    target = data.get("target", "unknown")
    stdout = data.get("stdout", "")
    status = data.get("status", "")
    safe_mode = status == "would_execute"

    flags: list[str] = []
    if stdout and not safe_mode and not data.get("error"):
        flags.append("rce:confirmed")
        first = stdout.splitlines()[0] if stdout.splitlines() else ""
        if "uid=0" in stdout or "root" in first:
            flags.append("rce:root_context")

    stats: dict[str, Any] = {
        "target": target,
        "stdout_len": len(stdout),
    }

    if safe_mode:
        summary = f"WOULD execute on {target} (safe_mode — not run)."
    elif data.get("error"):
        summary = f"vm_execute_command on {target} failed: {data['error'][:80]}"
    else:
        first_line = stdout.splitlines()[0][:80] if stdout else "(no output)"
        summary = f"RCE on {target}. Output: {first_line}"

    return summary, flags, stats


# ================================================================
# Dispatch table — maps technique_id to summarizer function.
# Add new entries as new techniques are implemented.
# ================================================================

_SUMMARIZERS: dict[str, Any] = {
    "discovery/whoami":                    _summarize_whoami,
    "discovery/enum_iam":                  _summarize_enum_iam,
    "discovery/enum_compute":              _summarize_enum_compute,
    "escalation/assume_role_chain":        _summarize_assume_role_chain,
    "lateral_movement/vm_execute_command":  _summarize_vm_execute_command,
}


# ================================================================
# Generic fallback for any technique without a registered
# summarizer. Produces a minimal summary from whatever keys exist.
# ================================================================

def _generic_summary(data: dict, technique_id: str) -> tuple[str, list[str], dict]:
    total = data.get("total")
    data.get("provider", "")
    if total is not None:
        summary = f"{technique_id} found {total} item(s)."
    else:
        keys = [k for k in data if k not in ("provider", "status", "principal")]
        summary = f"{technique_id} completed. Keys: {', '.join(keys[:4])}."
    return summary, [], {}


# ================================================================
# Public API
# ================================================================

def summarize(
    technique_id: str,
    tactic: str,
    provider: str,
    data: Any,
    *,
    ok: bool,
    ms: int,
    api_calls: int,
    error: str | None = None,
) -> AgentSummary:
    """Convert raw technique data to a compact AgentSummary.

    Args:
        technique_id: e.g. "discovery/enum_iam"
        tactic: e.g. "discovery"
        provider: e.g. "aws"
        data: The raw return value from execute(ctx)
        ok: Whether the technique succeeded
        ms: Duration in milliseconds
        api_calls: Number of API calls made
        error: Error message if ok is False

    Returns:
        AgentSummary — ready for compact JSON serialization
    """
    if not ok or data is None:
        return AgentSummary(
            technique=technique_id,
            tactic=tactic,
            provider=provider,
            ok=False,
            summary=error or "Technique failed.",
            risk_flags=[],
            stats={},
            ms=ms,
            api_calls=api_calls,
            error=error,
        )

    # --------------------------------------------------------
    # Normalize data — handle dataclasses and plain dicts.
    # --------------------------------------------------------
    if hasattr(data, "__dataclass_fields__"):
        from dataclasses import asdict
        data_dict: dict = asdict(data)
    elif isinstance(data, dict):
        data_dict = data
    else:
        data_dict = {}

    # --------------------------------------------------------
    # Dispatch to registered summarizer or fall back.
    # --------------------------------------------------------
    fn = _SUMMARIZERS.get(technique_id)
    if fn is not None:
        summary_text, risk_flags, stats = fn(data_dict, provider)
    else:
        summary_text, risk_flags, stats = _generic_summary(data_dict, technique_id)

    return AgentSummary(
        technique=technique_id,
        tactic=tactic,
        provider=provider,
        ok=True,
        summary=summary_text,
        risk_flags=risk_flags,
        stats=stats,
        ms=ms,
        api_calls=api_calls,
    )
