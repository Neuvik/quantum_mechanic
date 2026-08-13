# Quantum Mechanic — Operator Wiki

| | |
|---|---|
| **Version** | v1.0-rc3 |
| **Issued** | 2026-08-07 |
| **Last reviewed** | 2026-08-07 |
| **Status** | Active |

Quantum Mechanic (QM) is a cross-cloud offensive security framework covering
cloud and identity workflows across AWS, Azure, Entra, GCP, and OCI from a
single shell.

## Authorized Use

Use QM only for authorized security assessments, lab environments, or other
activities for which you have documented permission. You are responsible for
complying with applicable law, contracts, and system-owner requirements.

```
qm[acme-prod][aws:AKIA...]> run discovery/enum_iam
```

---

## Table of Contents

### Getting Started
1. [Getting Started](./Getting-Started.md) — install, first workspace, first run

### Command Reference
2. [Shell Reference](./Shell-Reference.md) — every command, every flag

### Guides
3. [Workspaces](./Workspaces.md) — create and manage engagements
4. [Credentials](./Credentials.md) — import, switch, inspect credentials
5. [Techniques](./Techniques.md) — browse, run, and understand techniques
6. [Evidence](./Evidence.md) — how QM records notes and attack paths
7. [Report](./Report.md) — engagement narrative and findings
8. [Agent Mode](./Agent-Mode.md) — the `ask` command and RAG agent

---

## Release History

See [Release Notes](./Release-Notes.md) for what changed in each version.

**Current:** `v1.0-rc3` — public release candidate (2026-08-07)

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0-rc3 | 2026-08-07 | Added authorized-use guidance and updated release metadata. |
