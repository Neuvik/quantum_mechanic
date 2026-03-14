# Getting Started

> **`🔓 PUBLIC`**

| | |
|---|---|
| **Version** | v0.1.0 |
| **Issued** | 2026-03-09 |
| **Last reviewed** | 2026-03-09 |
| **Status** | Active |

---

## 1. Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) for dependency management

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## 2. Installation

```bash
git clone <repo>
cd quantum_mechanic
uv sync
```

---

## 3. Launch the Shell

```bash
uv run qm
```

You will see the QM prompt:

```
qm> 
```

---

## 4. Create Your First Workspace

A workspace is an SQLite engagement database that holds credentials, discovered resources, and findings. Everything is scoped to a workspace.

```
qm> workspace create acme-assessment
✓ Workspace 'acme-assessment' created
qm[acme-assessment]>
```

---

## 5. Import a Credential

Import a credential for the cloud environment you are assessing.

**AWS (CLI profile):**
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

> **Note:** Credentials are stored encrypted in the workspace database. Secret material never appears in logs or the engagement report.

---

## 6. Set the Active Credential

```
qm[acme-assessment]> use 1
✓ Active credential: #1 (aws)
qm[acme-assessment][aws:1]>
```

---

## 7. Run Your First Technique

Identify who you are in the target environment:

```
qm[acme-assessment][aws:1]> run discovery/whoami
```

List what techniques are available for your active provider:

```
qm[acme-assessment][aws:1]> techniques
```

Run a technique directly by ID (shortcut — no `run` prefix needed):

```
qm[acme-assessment][aws:1]> discovery/enum_iam
```

---

## 8. View the Engagement Report

After running techniques, review what was found:

```
qm[acme-assessment][aws:1]> report
```

This renders the credential chain, technique timeline, and findings table inline.

---

## 9. Exit

```
qm> exit
```

---

## Next Steps

- [Shell Reference](./Shell-Reference.md) — every command and flag
- [Workspaces](./Workspaces.md) — managing multiple engagements
- [Credentials](./Credentials.md) — credential lifecycle and raw inspection
- [Techniques](./Techniques.md) — browsing, running, and reading technique docs

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| 0.1 | 2026-03-07 | Initial draft |
| 0.2 | 2026-03-09 | Fixed entry point (`uv run qm`), Python 3.12+, added version table and change log |
