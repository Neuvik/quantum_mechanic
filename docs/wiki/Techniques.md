# Techniques

> **`🔓 PUBLIC`**

| | |
|---|---|
| **Version** | v0.1.0 |
| **Issued** | 2026-03-09 |
| **Last reviewed** | 2026-03-09 |
| **Status** | Active |

---

## Browsing Techniques

List all techniques available for the active provider:

```
qm[ws][aws:1]> techniques

  ID                        Tactic          Providers     Safe  Description
  ────────────────────────  ──────────────  ────────────  ────  ────────────────────────
  discovery/whoami          discovery       aws az gcp o  ✓     Identify current identity
  discovery/enum_iam        discovery       aws az gcp o  ✓     Enumerate IAM permissions
```

The table is filtered by your active provider — techniques for other clouds are loaded but hidden until you switch credentials.

---

## Running Techniques

### Basic run
```
qm[ws][aws:1]> run discovery/whoami
```

### Shortcut (no `run` prefix)
```
qm[ws][aws:1]> discovery/whoami
```

### With parameters
```
qm[ws][aws:1]> run discovery/enum_iam --param max_roles=50
```

### Safe-check mode (read-only validation)
For techniques that support it, `--safe` validates conditions without making any state changes:
```
qm[ws][aws:1]> run escalation/compute_identity_abuse --safe

  ✓ Would succeed: AdminRole is attachable to EC2 instances you control
  ✗ Dry run — no changes made
```

### Execution Metrics
Every time a technique runs, Quantum Mechanic records operational telemetry alongside the result data:
- `api_calls` — The exact number of cloud API HTTP requests made during the run.
- `duration_ms` — The total elapsed execution time in milliseconds.

These metrics are visible in the JSON output when using the `qm --agent` API and are permanently logged into the workspace evidence pipeline.

---

## Reading Technique Documentation

Every technique ships with inline documentation explaining what it does,
how it works per provider, what the blue team should look for, and how to remediate.

```
qm[ws]> help discovery/enum_iam

  TECHNIQUE: discovery/enum_iam
  TACTIC:    Discovery (TA0007)
  MITRE:     T1087 — Account Discovery

  PURPOSE:
    Enumerate IAM policies, roles, and permissions attached to the
    current principal. Identifies admin-equivalent access and
    privilege escalation paths.

  HOW IT WORKS:
    AWS   — iam:ListAttachedUserPolicies, iam:SimulatePrincipalPolicy
    Azure — RBAC ListRoleAssignments for current principal
    GCP   — cloudresourcemanager.getIamPolicy on project
    OCI   — identity.ListPolicies filtered by compartment

  DETECTION (Blue Team):
    AWS   — CloudTrail: iam:SimulatePrincipalPolicy
    Azure — Azure Monitor: Microsoft.Authorization/roleAssignments/read
    GCP   — Cloud Audit Logs: GetIamPolicy on cloudresourcemanager

  SAFE: Yes — read-only enumeration
```

---

## Hot-Reloading

After adding or editing a technique file, reload without restarting QM:

```
qm[ws]> reload
✓ Reloaded — 12 technique(s) loaded
```

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| 1.0 | 2026-03-09 | Initial |
| 1.1 | 2026-03-09 | Added Execution Metrics documentation |
