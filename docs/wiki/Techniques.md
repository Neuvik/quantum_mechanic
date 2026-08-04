# Techniques

| | |
|---|---|
| **Version** | v1.0-rc2 |
| **Issued** | 2026-08-04 |
| **Last reviewed** | 2026-08-04 |
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

Every technique ships with inline metadata and source-level header comments.
In the public `v1.0-rc2` shell, `help <technique>` shows the concise
operator-facing summary: technique ID, tactic, MITRE mapping, providers,
safety, parameters, and examples.

```
qm[ws]> help discovery/enum_iam

  TECHNIQUE: discovery/enum_iam
  TACTIC:    Discovery (TA0007)
  MITRE:     T1087 — Account Discovery

  Description: Enumerate IAM policies, roles, and permissions
  Providers: aws, azure, gcp, oci
  Safe: Yes
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
| v1.0-rc2 | 2026-08-04 | Public technique guide aligned to the shipped shell output, including execution metrics and current command behavior |
