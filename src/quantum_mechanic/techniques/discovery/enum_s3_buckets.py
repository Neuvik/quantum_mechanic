# ================================================================
# TECHNIQUE: discovery/enum_s3_buckets
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1580 — Cloud Infrastructure Discovery
#
# PURPOSE:   Brute-force S3 bucket names from a wordlist and report
#            which buckets exist, their region, and their ACL grants.
#            Works unauthenticated (HTTP HEAD) and adds ACL detail
#            when an active AWS credential is available.
#
# PROVIDERS: aws (optional — unauthenticated scan works with no cred)
#
# HOW IT WORKS:
#   1. Reads candidate names from a wordlist file.
#      If --domain is provided, three variants are checked per word:
#        <word>.<domain>  /  <domain>-<word>  /  <domain>.<word>
#   2. For each candidate, sends an HTTP HEAD to:
#        https://<candidate>.s3.amazonaws.com/
#      - 200 / 403 → bucket exists (403 = exists but access denied)
#      - 301        → bucket exists in a different region (Location header)
#      - 404 / NoSuchBucket → does not exist
#   3. When an active AWS credential is loaded, attempts
#      s3:GetBucketAcl on each found bucket to surface:
#        AllUsers:READ  — public read (the interesting finding)
#        AllUsers:WRITE — public write (critical)
#        AuthUsers:READ — any authenticated AWS user can read
#
# WORDLISTS:
#   Built-in lists ship in src/quantum_mechanic/data/wordlists/ and
#   can be referenced by name (without extension):
#     wordlist=s3-common        ~65 high-signal names
#     wordlist=s3-permutations  ~100 role/environment permutations
#   Pass a filesystem path for custom lists:
#     wordlist=/path/to/mylist.txt
#
# OPTIONS:
#   wordlist (required) — built-in name or file path
#   domain   (optional) — company name/domain to permute against each word
#   threads  (optional) — concurrent HTTP workers (default: 20)
#
# DETECTION (Blue Team):
#   High-volume unauthenticated HEAD requests from a single IP to
#   s3.amazonaws.com virtual-hosted URLs. No CloudTrail event for
#   unauthenticated existence checks. GetBucketAcl does appear in
#   CloudTrail under the bucket owner's account.
#
# REFERENCES:
#   https://github.com/sa7mon/s3scanner
#   https://attack.mitre.org/techniques/T1580/
#
# SAFE:     Yes — read-only probes, no state changes.
# ================================================================

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from quantum_mechanic.core.context import ExecutionContext
from quantum_mechanic.core.technique import Parameter, technique

logger = logging.getLogger(__name__)

_WORDLISTS_DIR = Path(__file__).parent.parent.parent / "data" / "wordlists"

LOOT_ITEMS_KEY = "buckets"
LOOT_SCHEMA = [
    ("bucket", "Bucket", "bold cyan"),
    ("status", "Status", "green"),
    ("region", "Region", "dim"),
    ("acl", "ACL", "bold red"),
]


# ----------------------------------------------------------------
# Operational Formatter
# ----------------------------------------------------------------
def format_s3_result(result: Any) -> None:
    from rich import box
    from rich.table import Table

    from quantum_mechanic.shell.formatters import console

    data = result.data

    if data.get("error"):
        console.print(f"  [bold red]✗[/bold red] {data['error']}")
        return

    buckets = data.get("buckets", [])
    total_checked = data.get("total_checked", 0)
    found = [b for b in buckets if b.get("status") != "not_exist"]

    console.print(
        f"  Checked [bold]{total_checked}[/bold] names — "
        f"[bold green]{len(found)}[/bold green] bucket(s) found"
    )

    if not found:
        return

    tbl = Table(box=box.ROUNDED, border_style="dim")
    tbl.add_column("Bucket", style="bold cyan")
    tbl.add_column("Status")
    tbl.add_column("Region", style="dim")
    tbl.add_column("ACL", style="bold")

    for b in found:
        status = b.get("status", "")
        acl = b.get("acl", "")
        acl_style = "bold red" if "AllUsers" in acl else "dim"
        tbl.add_row(
            b.get("bucket", ""),
            f"[green]{status}[/green]" if status == "exists" else f"[yellow]{status}[/yellow]",
            b.get("region", ""),
            f"[{acl_style}]{acl}[/{acl_style}]" if acl else "[dim]—[/dim]",
        )

    console.print(tbl)


@technique(
    technique_id="discovery/enum_s3_buckets",
    tactic="discovery",
    mitre_id="T1580",
    providers=[],
    severity="info",
    safe=True,
    description="Brute-force S3 bucket names from a wordlist; reports existence and public ACLs.",
    formatter=format_s3_result,
    loot_schema=LOOT_SCHEMA,
    loot_items_key=LOOT_ITEMS_KEY,
    parameters=[
        Parameter(
            "wordlist",
            "Built-in wordlist name (s3-common, s3-permutations) or path to a file.",
            required=True,
            example="s3-common",
        ),
        Parameter(
            "domain",
            "Company name or domain to permute with each word (e.g. 'acme' or 'acme.com').",
            required=False,
            example="acme",
        ),
        Parameter(
            "threads",
            "Number of concurrent HTTP workers.",
            required=False,
            default="20",
            example="20",
        ),
    ],
)
def execute(ctx: ExecutionContext) -> dict[str, Any]:
    wordlist_param = ctx.get_param("wordlist")
    domain = ctx.get_param("domain") or ""
    try:
        threads = int(ctx.get_param("threads") or 20)
    except ValueError:
        threads = 20

    # ── Resolve wordlist ─────────────────────────────────────────
    names = _load_wordlist(wordlist_param)
    if names is None:
        return {
            "error": f"Wordlist not found: '{wordlist_param}'. Use a built-in name (s3-common, s3-permutations) or a valid file path.",
            "buckets": [],
        }

    # ── Build candidate list ─────────────────────────────────────
    candidates: list[str] = []
    stripped_domain = domain.split(".")[0] if domain else ""
    for word in names:
        word = word.strip()
        if not word or word.startswith("#"):
            continue
        candidates.append(word)
        if stripped_domain:
            candidates.append(f"{word}-{stripped_domain}")
            candidates.append(f"{stripped_domain}-{word}")
            candidates.append(f"{stripped_domain}.{word}")
            candidates.append(f"{word}.{stripped_domain}")

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    ctx.info(f"Scanning {len(unique)} bucket name candidates with {threads} threads...")

    # ── HTTP existence check ─────────────────────────────────────
    lock = threading.Lock()
    results: list[dict[str, Any]] = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"

    def _check(name: str) -> dict[str, Any] | None:
        url = f"https://{name}.s3.amazonaws.com/"
        try:
            resp = session.head(url, timeout=5, allow_redirects=False)
            if resp.status_code == 404:
                return None
            if resp.status_code in (200, 403):
                region = resp.headers.get("x-amz-bucket-region", "unknown")
                return {"bucket": name, "status": "exists", "region": region, "acl": ""}
            if resp.status_code == 301:
                region = resp.headers.get("x-amz-bucket-region", "unknown")
                return {"bucket": name, "status": "exists", "region": region, "acl": ""}
        except Exception as exc:
            logger.debug("HEAD %s failed: %s", name, exc)
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_check, name): name for name in unique}
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                with lock:
                    results.append(hit)

    # ── ACL enrichment (requires active AWS credential) ──────────
    if results and ctx.session is not None:
        ctx.info(f"Found {len(results)} bucket(s) — fetching ACLs...")
        s3 = ctx.session.client("s3")
        for bucket in results:
            try:
                acl_resp = s3.get_bucket_acl(Bucket=bucket["bucket"])
                grants = _summarise_acl(acl_resp.get("Grants", []))
                bucket["acl"] = grants
            except Exception as exc:
                logger.debug("GetBucketAcl %s failed: %s", bucket["bucket"], exc)
    elif results:
        ctx.info("No active AWS credential — skipping ACL check. Use 'import aws' to enable.")

    # Emit not_exist rows only in the full result (not in loot)
    all_rows = results[:]
    return {
        "buckets": all_rows,
        "total_checked": len(unique),
    }


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------


def _load_wordlist(param: str | None) -> list[str] | None:
    """Resolve built-in name or file path → list of lines."""
    if not param:
        return None

    # Try built-in first
    builtin = _WORDLISTS_DIR / f"{param}.txt"
    if builtin.exists():
        return builtin.read_text(encoding="utf-8").splitlines()

    # Try as absolute/relative path
    path = Path(param)
    if path.exists():
        return path.read_text(encoding="utf-8").splitlines()

    return None


def _summarise_acl(grants: list[dict]) -> str:
    """Collapse raw ACL grants into a readable summary string."""
    _GROUP_URIS = {
        "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthUsers",
    }
    summary: dict[str, list[str]] = {}
    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        label = _GROUP_URIS.get(uri)
        if label:
            perm = grant.get("Permission", "")
            summary.setdefault(label, []).append(perm)

    if not summary:
        return ""
    return " | ".join(f"{k}: [{', '.join(v)}]" for k, v in summary.items())
