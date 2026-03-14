# Contributing to Quantum Mechanic

Quantum Mechanic is an offensive security framework. Contributing a new
technique means writing a Python file that teaches the tool a new attack primitive
and documents it for both operators and defenders.

This guide covers everything you need to write your first technique.

---

## Before You Start

Read these first:

- [`docs/architecture/vision.md`](docs/architecture/vision.md) — what QM is and is not
- [`docs/architecture/harness.md`](docs/architecture/harness.md) — what the harness gives you
- [`docs/architecture/modules.md`](docs/architecture/modules.md) — three-layer architecture

If you want to understand what a finished technique looks like, read
[`src/quantum_mechanic/techniques/discovery/whoami.py`](src/quantum_mechanic/techniques/discovery/whoami.py).
It is the simplest possible real technique in the codebase.

---

## Scaffold Generator

Don't start from a blank file. Use the YAML-to-technique generator to produce
the block comment, decorator, per-cloud stubs, and test file automatically:

```bash
# Copy the example and edit it
cp scripts/examples/lambda_role_abuse.yaml scripts/examples/my_technique.yaml
# Edit my_technique.yaml with your technique's details

# Preview the output
uv run scripts/gen_technique.py scripts/examples/my_technique.yaml --dry-run

# Write the files
uv run scripts/gen_technique.py scripts/examples/my_technique.yaml
```

The generator creates:
- `src/quantum_mechanic/techniques/<tactic>/<name>.py` — block comment + decorator + stubs
- `tests/unit/techniques/<tactic>/test_<name>.py` — test scaffold

Then fill in the stubs and tests. Nothing is overwritten without `--force`.


---

## What Is a Technique?

A technique is a single Python file in `src/quantum_mechanic/techniques/<tactic>/`.

It contains:

1. A structured block comment documenting what the technique does — purpose, how it works per cloud, detection guidance
2. A decorated function called `execute` that receives `ctx` and does the work
3. A unit test file at `tests/unit/techniques/<tactic>/test_<name>.py`

That's it. The harness handles authentication, API logging, workspace storage,
pagination, retries, and report generation. You write the attack logic.

---

## Directory Structure

Techniques live under ATT&CK tactic directories:

```
src/quantum_mechanic/techniques/
├── discovery/
│   ├── whoami.py
│   └── enum_iam.py
├── escalation/
│   ├── compute_identity_abuse.py
│   └── assume_role_chain.py
├── lateral_movement/
│   └── azure_run_command.py
├── credential_access/
│   └── ssrf_imds.py
└── persistence/          ← v2
```

Pick the tactic that matches your technique's MITRE ATT&CK classification.
If you're unsure, check [attack.mitre.org/matrices/enterprise/cloud](https://attack.mitre.org/matrices/enterprise/cloud/).

---

## Step 1: The Block Comment

Every technique file starts with a standardized block comment. This is not optional —
it is the primary documentation for operators running the technique and defenders
reading the report. The format uses `# ===` delimiters and labeled fields so it
remains readable as plain text, in the shell, and in generated reports.

```python
# ================================================================
# TECHNIQUE: discovery/enum_storage_buckets
# ----------------------------------------------------------------
# TACTIC:    Discovery (TA0007)
# TECHNIQUE: T1619 — Cloud Storage Object Discovery
#
# PURPOSE:   List all storage buckets/containers accessible to the
#            current principal. Checks for public access misconfig.
#
# PROVIDERS: aws, azure, gcp
#
# HOW IT WORKS:
#   AWS   — s3:ListBuckets returns all buckets in the account.
#           Then s3:GetBucketAcl + s3:GetBucketPolicy per bucket
#           to detect public access.
#   Azure — storage:List across subscriptions to find storage
#           accounts, then list containers per account.
#   GCP   — storage.buckets.list within accessible projects.
#
# DETECTION (Blue Team):
#   AWS   — CloudTrail: s3:ListBuckets (low noise, always logged)
#           s3:GetBucketAcl, s3:GetBucketPolicy (per bucket)
#           Alert on burst: >20 GetBucketPolicy calls in <30s
#
#   Azure — Activity Log: Microsoft.Storage/storageAccounts/read
#           Bulk reads across subscriptions are unusual for users.
#
#   GCP   — Admin Activity: storage.buckets.list
#           Caller: service accounts listing across projects = alert
#
# REFERENCES:
#   - https://hackingthe.cloud/aws/enumeration/s3_enum/
#   - https://rhinosecuritylabs.com/aws/s3-security-assessment/
#
# SAFE:     Yes — read-only, no state changes.
# ================================================================
```

**Required fields:** `TECHNIQUE`, `TACTIC`, `TECHNIQUE` (MITRE), `PURPOSE`,
`PROVIDERS`, `HOW IT WORKS` (one entry per cloud), `DETECTION` (one entry per
cloud), `SAFE`.

**SAFE flag:** Mark `Yes` only if the technique makes zero state changes and cannot
be destructive even with max permissions. Mark `No` if it creates, modifies, or
deletes any resource.

---

## Step 2: The @technique Decorator

```python
from quantum_mechanic.core.technique import technique

@technique(
    technique_id="discovery/enum_storage_buckets",  # tactic/kebab-case-name
    tactic="discovery",                              # ATT&CK tactic
    mitre_id="T1619",                               # ATT&CK technique ID
    providers=["aws", "azure", "gcp"],              # which clouds this works on
    severity="info",                                 # info | low | medium | high | critical
    safe=True,                                       # must match SAFE in block comment
    description="List all storage buckets accessible to the current principal.",
)
def execute(ctx: ExecutionContext) -> ...:
    ...
```

**`technique_id`** must match the filename path: `discovery/enum_storage_buckets`
maps to `techniques/discovery/enum_storage_buckets.py`.

**`providers`** is what the technique *currently supports*, not what it eventually
will. If you only implement AWS, write `["aws"]`. Azure and GCP can be added later.

> **Module parity expectation:** If the attack pattern is architectural (compute
> runs → SA attached → SA has permissions), open a GitHub issue for each unimplemented
> cloud at PR time. Tag them `module-parity`. They should not block your PR but they
> should exist. The goal is full four-cloud coverage, not AWS-first permanence.


**`severity`** reflects the access level obtained if this technique finds something:
- `info` — confirms identity, enumerates resources, no escalation
- `low` — reads sensitive config, no credential access
- `medium` — accesses secrets, exposes attack surface
- `high` — privilege escalation, lateral movement achieved  
- `critical` — admin-equivalent access obtained

---

## Step 3: The execute Function

The function receives `ctx` (`ExecutionContext`) and uses it for everything.
You do not call boto3, azure-sdk, or google-cloud libraries directly.

```python
def execute(ctx: ExecutionContext):
    # ctx.provider tells you which cloud you're on: "aws", "azure", "gcp", "oci"
    # ctx.storage, ctx.identity, ctx.compute are provider-agnostic abstractions.
    # The abstractions handle auth and response normalization — you write logic.
    me = ctx.whoami()

    buckets = ctx.storage.list_buckets()

    for bucket in buckets:
        acl = ctx.storage.get_bucket_acl(bucket.name)

        if acl.is_public():
            # Branch per provider to give cloud-specific remediation and detection.
            # The finding itself is always the same structure.
            if ctx.provider == "aws":
                recommendation = (
                    "Remove public ACL. Enable S3 Block Public Access at the account level."
                )
                detection = "CloudTrail: s3:GetBucketAcl from this principal"
            elif ctx.provider == "azure":
                recommendation = (
                    "Set container access to Private. Disable anonymous blob access "
                    "on the storage account."
                )
                detection = (
                    "Activity Log: Microsoft.Storage/storageAccounts/"
                    "blobServices/containers/read"
                )
            elif ctx.provider == "gcp":
                recommendation = (
                    "Remove allUsers and allAuthenticatedUsers IAM bindings from the bucket."
                )
                detection = "Cloud Audit Logs: storage.buckets.getIamPolicy"
            else:  # oci
                recommendation = (
                    "Remove public pre-authenticated requests. "
                    "Set bucket visibility to Private."
                )
                detection = "OCI Audit: GetBucket / ListObjects from anonymous principals"

            ctx.finding(
                title=f"Public storage bucket: {bucket.name}",
                severity="high",
                evidence={
                    "bucket": bucket.name,
                    "acl": acl.raw,
                    "region": bucket.region,
                },
                recommendation=recommendation,
                mitre_id="T1619",
                detection_log=detection,
            )

    # Store discovered resources in the workspace for downstream techniques
    ctx.workspace.add_resources(buckets)

    return buckets
```

**Key rules:**
- Never instantiate a cloud SDK client yourself — always go through `ctx`
- Always call `ctx.finding(...)` when you confirm a exploitable condition
- Always call `ctx.workspace.add_resources(...)` for enumerated assets
- Return a meaningful result — the shell and agent mode display it

---

## Step 4: Write the Unit Test

Every technique needs a unit test that mocks the provider. No live cloud calls
in unit tests.

```
tests/unit/techniques/discovery/test_enum_storage_buckets.py
```

```python
from unittest.mock import MagicMock, patch
from quantum_mechanic.techniques.discovery.enum_storage_buckets import execute


def test_public_bucket_creates_finding():
    ctx = MagicMock()
    ctx.storage.list_buckets.return_value = [
        MagicMock(name="public-logs", region="us-east-1"),
    ]
    ctx.storage.get_bucket_acl.return_value = MagicMock(is_public=lambda: True)

    execute(ctx)

    ctx.finding.assert_called_once()
    call_kwargs = ctx.finding.call_args.kwargs
    assert call_kwargs["severity"] == "high"
    assert "public-logs" in call_kwargs["title"]


def test_private_bucket_no_finding():
    ctx = MagicMock()
    ctx.storage.list_buckets.return_value = [
        MagicMock(name="private-data", region="us-east-1"),
    ]
    ctx.storage.get_bucket_acl.return_value = MagicMock(is_public=lambda: False)

    execute(ctx)

    ctx.finding.assert_not_called()
```

Run tests with:

```bash
uv run pytest tests/unit/techniques/discovery/test_enum_storage_buckets.py -v
```

---

## Step 5: Register Your Technique

The loader auto-discovers techniques by file path — no registration file needed.
Drop your file in the right tactic directory and it appears in the shell.

Verify it loads:

```bash
uv run qm
> list
```

Your technique should appear as `discovery/enum-storage-buckets`.

---

## What Not To Do

| ❌ Don't | ✅ Do instead |
|---|---|
| Call `boto3.client(...)` directly | Use `ctx.storage`, `ctx.identity`, `ctx.compute` |
| Catch and swallow exceptions | Let them propagate — the harness reports them |
| Print to stdout | Use `ctx.finding()` and `ctx.workspace` |
| Write to files | Return data and let the harness generate evidence |
| Hard-code regions or account IDs | Use what's in `ctx.session` |
| Implement for all 4 clouds at once | Ship one cloud, mark `providers=["aws"]`, open issues for the others |
| Skip the block comment | It is required. There is no step that skips it. |

---

## Coverage and Quality Gates

Before opening a PR:

```bash
# Tests must pass
uv run pytest tests/unit/

# Coverage must be ≥80% on your technique file
uv run pytest tests/unit/techniques/<tactic>/test_<name>.py --cov=quantum_mechanic.techniques.<tactic>.<name> --cov-report=term-missing

# Linting
uv run ruff check src/quantum_mechanic/techniques/<tactic>/<name>.py
uv run mypy src/quantum_mechanic/techniques/<tactic>/<name>.py
```

---

## Scope of Coverage

QM does not try to cover every possible attack path at once. Current focus is:

**v1 (in progress):** Discovery, Privilege Escalation via compute identity, Credential Access via metadata service — on AWS and Azure.

**v2:** GCP and OCI parity, Lateral Movement, Persistence, additional AWS/Azure escalation paths.

If you want to contribute a v2 technique today, open an issue first to discuss — it may conflict with planned implementation decisions.

---

## Module Parity Principle

The fact that OCI, GCP, or Azure has fewer *documented* attack paths than AWS
does not mean fewer attacks are possible. It means less public security research
has been published against those clouds.

The structural pattern is consistent across all four providers:

```
Compute resource starts running
    → Cloud identity is attached (EC2 role / MSI / GCP SA / OCI Dynamic Group)
    → Identity has IAM permissions
    → Code running in that resource can use those permissions
    → Attacker with code execution = attacker with those IAM permissions
```

When implementing a technique, apply this rule:

> **If an attack path exploits the pattern above and the service architecture
> is analogous on another cloud, the attack is presumed applicable until
> proven otherwise.**

Service equivalents across clouds:

| Pattern | AWS | Azure | GCP | OCI |
|---|---|---|---|---|
| Serverless compute + SA | Lambda | Function App | Cloud Run | Functions |
| Managed notebook | SageMaker | — | Vertex Workbench | Data Science |
| Build pipeline | CodeBuild | Azure Pipelines | Cloud Build | DevOps Build |
| Managed orchestration | Step Functions | Logic Apps | Cloud Composer | Events + Functions |
| Container registry | ECR | ACR | Artifact Registry | Container Registry |
| Managed Kubernetes | EKS | AKS | GKE | OKE |
| Stream trigger | Kinesis | Event Hubs | Pub/Sub | Streaming |
| Managed bastion | Session Manager | Azure Bastion | IAP Tunnel | Bastion |

**In practice:** If you implement `escalation/lambda_execution_role_abuse` for AWS,
open parity issues for `escalation/azure_function_app_msi`,
`escalation/gcp_cloud_run_sa`, and `escalation/oci_functions_resource_principal`
at PR time. Those are follow-on work items, not blockers.

---

## Opening a Pull Request

1. Run all tests and quality gates
2. Write a PR description that includes:
   - What attack this technique implements
   - Which providers are supported
   - Which MITRE technique it maps to
   - What evidence it produces
   - What defenders should alert on

PRs that skip the block comment or unit tests will not be reviewed until those are added.

---

## Questions

Open a GitHub Discussion or check the architecture docs in `docs/architecture/`.
The [harness doc](docs/architecture/harness.md) covers what `ctx` can do.
The [modules doc](docs/architecture/modules.md) covers the three-layer design.
