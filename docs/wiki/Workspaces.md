# Workspaces

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

A **workspace** is a self-contained SQLite engagement database. Every credential, discovered resource, finding, and API call is stored in the workspace. You can have many workspaces — one per engagement.

**Location on disk:** `~/.quantum_mechanic/workspaces/<name>.db`

Set `QM_WORKSPACE_DIR` before starting QM to use a different workspace root;
set `QM_HOME` to relocate the broader local QM state directory.

---

## Commands

### Create a workspace
```
qm> workspace create acme-assessment
✓ Workspace 'acme-assessment' created
qm[acme-assessment]>
```

### Load an existing workspace
```
qm> workspace load acme-assessment
✓ Workspace 'acme-assessment' loaded
qm[acme-assessment]>
```

### List all workspaces
```
qm> workspace list
  acme-assessment    2026-03-09   (3 credentials, 12 findings)
  beta-corp-q1       2026-02-14   (1 credential,  0 findings)
```

---

## What a Workspace Stores

| Data | Description |
|------|-------------|
| **Credentials** | Every key, token, and assumed role — encrypted at rest |
| **Principals** | Cloud identities discovered during assessment |
| **Resources** | Compute, storage, databases, functions |
| **Findings** | Proven attack paths with severity and evidence |
| **API log** | Append-only log of every API call made |
| **Relationships** | Typed edges (can_assume, attached_to, escalation_path) |

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0.0 | 2026-09-14 | General availability release. |
| v1.0-rc3 | 2026-08-07 | Documented configurable state and workspace locations. |
| v1.0-rc2 | 2026-08-04 | Public workspace guide aligned to the shipped workspace-first operator flow |
