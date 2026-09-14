# Quantum Mechanic — Operator Wiki

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

One shell for cloud offense. Import a credential, run discovery, escalate,
move laterally, and generate a report. QM handles the evidence pipeline
and credential chain tracking so you can focus on the assessment.

Covers AWS, Azure, Entra ID, GCP, and OCI from a single prompt.

```
qm[acme-prod][aws:AKIA...]> run discovery/enum_iam
```

## Authorized Use

QM is for authorized assessments, labs, and sanctioned red team ops only.
Have documented permission before you point it at anything.

---

## Pages

| | |
|---|---|
| [Getting Started](./Getting-Started.md) | Install, first workspace, first technique |
| [Shell Reference](./Shell-Reference.md) | Every command and flag |
| [Workspaces](./Workspaces.md) | Create and manage engagement databases |
| [Credentials](./Credentials.md) | Import, switch, inspect credentials |
| [Techniques](./Techniques.md) | Browse, run, and read technique docs |
| [Evidence](./Evidence.md) | How QM records API logs and attack paths |
| [Report](./Report.md) | Engagement narrative and findings |
| [Agent Mode](./Agent-Mode.md) | The `ask` command and local RAG advisor |

---

## Release History

See [Release Notes](./Release-Notes.md) for what changed in each version.

**Current:** `v1.0.0` — general availability release (2026-09-14)

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0.0 | 2026-09-14 | General availability release. |
| v1.0-rc3 | 2026-08-07 | Added authorized-use guidance and updated release metadata. |
