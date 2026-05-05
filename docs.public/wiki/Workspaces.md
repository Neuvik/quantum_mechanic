# Workspaces

> **`🔓 PUBLIC`**

| | |
|---|---|
| **Version** | v0.1.0 |
| **Issued** | 2026-03-09 |
| **Last reviewed** | 2026-03-09 |
| **Status** | Active |

A **workspace** is a self-contained SQLite engagement database. Every credential, discovered resource, finding, and API call is stored in the workspace. You can have many workspaces — one per engagement.

**Location on disk:** `~/.quantum_mechanic/workspaces/<name>.db`

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
| 1.0 | 2026-03-09 | Initial |
