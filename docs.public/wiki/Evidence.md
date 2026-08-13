# Evidence Pipeline

| | |
|---|---|
| **Version** | v1.0-rc3 |
| **Issued** | 2026-08-07 |
| **Last reviewed** | 2026-08-07 |
| **Status** | Active |

Quantum Mechanic strictly enforces evidence retention. Every technique run, API call, and finding is persistently recorded in the workspace.

As a byproduct of the engagement, the framework automatically generates human-readable Markdown notes and an attack path narrative that can be loaded into tools like Obsidian or VS Code.

---

## Workspace Evidence Directory

All markdown artifacts are saved inside the workspace directory (`~/.quantum_mechanic/workspaces/<workspace_name>/`).

### 1. Technique Run Notes (`techniques/`)

Every time a technique is executed, a Markdown file is created (or updated with the latest run timestamp) detailing exactly what happened:

```
~/.quantum_mechanic/workspaces/<name>/
  techniques/
    discovery/
      whoami.md
      enum_iam.md
    privilege_escalation/
      compute_identity_abuse.md
```

**What these files contain:**
- Technique ID, Tactic, and Provider
- Date and Time of execution
- Principal used (who performed the action)
- Formatted results summary
- Raw API calls and responses (in collapsible `<details>` tags to keep the file clean)

*These files are completely idempotent; re-running a technique overwrites its note with the freshest state.*

### 2. Finding Notes (`findings/`)

When a technique uncovers a vulnerability, misconfiguration, or abuse path, a standalone Markdown note is created for that specific finding.

```
~/.quantum_mechanic/workspaces/<name>/
  findings/
    CRIT-001_domain_admin_privesc.md
    HIGH-002_public_s3_bucket.md
```

---

## ATTACK_PATH.md

The "money doc" of the engagement. 

After *every* technique run, QM dynamically re-generates a single file at the root of the workspace:
`~/.quantum_mechanic/workspaces/<name>/ATTACK_PATH.md`

This file is a structured narrative of the entire engagement up to the current moment. (It powers the `report` shell command, but in an archival-friendly Markdown format).

**It contains:**
1. **Credential Chain:** A visual tree showing exactly how each identity was acquired (e.g., initial access → assumed role A → assumed role B).
2. **Technique Timeline:** A strict chronological log of every action taken and its result.
3. **Findings Summary:** A table of all findings sorted by severity.

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0-rc3 | 2026-08-07 | Corrected the technique-artifact tactic directory example. |
| v1.0-rc2 | 2026-08-04 | Public evidence guide aligned to the shipped workspace artifact layout and report pipeline |
