# Techniques

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

---

## Browsing

`techniques` shows everything loaded for the active provider:

```
qm[ws][aws:1]> techniques

  ID                        Tactic          Providers     Safe  Description
  ────────────────────────  ──────────────  ────────────  ────  ────────────────────────
  discovery/whoami          discovery       aws az gcp o  ✓     Identify current identity
  discovery/enum_iam        discovery       aws az gcp o  ✓     Enumerate IAM permissions
```

Techniques for other clouds are loaded but hidden until you switch credentials.

---

## Running

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
qm[ws][aws:1]> run escalation/assume_role_chain --safe

  ✓ Would succeed: AdminRole is attachable to EC2 instances you control
  ✗ Dry run — no changes made
```

### Execution Metrics
Every run records `api_calls` (the exact number of cloud API HTTP requests) and `duration_ms` (total elapsed time). Both are visible in `qm --agent` JSON output and permanently logged into the workspace evidence pipeline.

---

## Inline Docs

`help <technique>` shows the operator-facing summary: ID, tactic, MITRE mapping, providers, safety mode, parameters, and examples.

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
| v1.0.0 | 2026-09-14 | General availability release. |
| v1.0-rc3 | 2026-08-07 | Corrected the safe-check example and updated release metadata. |
| v1.0-rc2 | 2026-08-04 | Public technique guide aligned to the shipped shell output, including execution metrics and current command behavior |
