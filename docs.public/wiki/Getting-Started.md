# Getting Started

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

---

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) for dependency management

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## Install

```bash
cd /path/to/quantum_mechanic
uv sync
```

QM stores local state under `~/.quantum_mechanic` by default. Override with environment variables if you need the state somewhere else:

```bash
export QM_HOME=/secure/qm-state
export QM_WORKSPACE_DIR=/secure/qm-workspaces
```

---

## Launch

```bash
uv run qm
```

```
qm>
```

---

## Create a Workspace

Everything in QM is scoped to a workspace: an SQLite database that holds credentials, discovered resources, evidence, and findings for one engagement.

```
qm> workspace create acme-assessment
✓ Workspace 'acme-assessment' created
qm[acme-assessment]>
```

---

## Import a Credential

Pick the provider you're assessing and bring a credential in.

**AWS (named profile):**
```
qm[acme-assessment]> import aws --profile default
✓ Credential #1 added: AWS profile 'default'
```

**Azure (CLI session):**
```
qm[acme-assessment]> import azure --default
✓ Credential #1 added: Azure CLI session
```

**GCP (application default):**
```
qm[acme-assessment]> import gcp --default
✓ Credential #1 added: GCP application default credentials
```

**OCI (config file):**
```
qm[acme-assessment]> import oci --default
✓ Credential #1 added: OCI config (DEFAULT profile)
```

Credentials are encrypted at rest in the workspace database. Secret material never appears in logs or the engagement report.

---

## Activate and Confirm

Set the credential you want to operate with, then confirm your identity in the target environment before you do anything else:

```
qm[acme-assessment]> use 1
✓ Active credential: #1 (aws)
qm[acme-assessment][aws:1]> run discovery/whoami
```

This is the "who am I, and what can I reach?" step. Always run it first.

---

## Run Techniques

List what's available for your active provider:

```
qm[acme-assessment][aws:1]> techniques
```

Run by ID (either form works):

```
qm[acme-assessment][aws:1]> run discovery/enum_iam
qm[acme-assessment][aws:1]> discovery/enum_iam
```

---

## Generate the Report

After running techniques, pull the engagement report:

```
qm[acme-assessment][aws:1]> report
```

Renders the credential chain, technique timeline, and findings inline.

---

## Exit

```
qm> exit
```

---

## Next Steps

- [Shell Reference](./Shell-Reference.md) — every command and flag
- [Workspaces](./Workspaces.md) — managing multiple engagements
- [Credentials](./Credentials.md) — credential lifecycle, raw inspection, Entra token flows
- [Techniques](./Techniques.md) — browsing, running, and reading inline technique docs

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0.0 | 2026-09-14 | General availability release. Tightened prose. |
| v1.0-rc3 | 2026-08-07 | Documented state-location environment variables and updated release metadata. |
| 0.1 | 2026-03-07 | Initial draft |
| 0.2 | 2026-03-09 | Fixed entry point (`uv run qm`), Python 3.12+, added version table and change log |
