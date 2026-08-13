# Shell Reference

| | |
|---|---|
| **Version** | v1.0-rc3 |
| **Issued** | 2026-08-07 |
| **Last reviewed** | 2026-08-07 |
| **Status** | Active |

Complete reference for every command available in the `qm` interactive shell.

**Prompt format:** `qm[<workspace>][<provider>:<cred-id>]>`

---

## Workspace Commands

| Command | Description |
|---------|-------------|
| `workspace create <name>` | Create a new engagement workspace |
| `workspace load <name>` | Open an existing workspace |
| `workspace list` | List all workspaces on disk |

**Details:** See [Workspaces](./Workspaces.md)

---

## Credential Commands

| Command | Description |
|---------|-------------|
| `import aws --profile <name>` | Import an AWS CLI named profile |
| `import aws --access-key` | Import AWS access key + secret interactively |
| `import azure --default` | Import Azure CLI session credentials |
| `import azure --client-id <id> --client-secret <s> --tenant-id <tenant-id>` | Import service principal |
| `import gcp --default` | Import GCP application default credentials |
| `import gcp --key-file <path>` | Import GCP service account key JSON |
| `import oci --default` | Import OCI config file (DEFAULT profile) |
| `import oci --profile <name>` | Import OCI named profile |
| `creds` | List all credentials with status |
| `creds --active` | List active credentials only |
| `creds delete <id>` | Remove credential by ID |
| `use <id>` | Set credential `<id>` as active |
| `raw <id>` | Show raw JSON for credential or principal `<id>` |
| `acquire entra <method>` | Acquire Entra tokens interactively |
| `export entra <format>` | Export or describe current Entra token material |

**Details:** See [Credentials](./Credentials.md)

---

## Technique Commands

| Command | Description |
|---------|-------------|
| `techniques` | List all techniques for the active provider |
| `run <technique_id>` | Execute a technique |
| `<technique_id>` | Shortcut — runs technique directly (no `run` prefix) |
| `run <id> --param key=value` | Execute with parameters |
| `run <id> --safe` | Run in safe-check mode (read-only validation) |
| `help <technique_id>` | Show inline technique documentation |
| `info <technique_id>` | Alias for `help` |
| `reload` | Hot-reload technique modules without restarting |
| `playbook list` / `playbook run <name>` | Manage YAML playbooks |
| `loot` / `loot <technique_id>` | View saved loot |
| `activity` | View workspace activity log |
| `check-ca-bypasses` | Analyze stored CA policy data for bypasses |

**Details:** See [Techniques](./Techniques.md)

---

## Reporting Commands

| Command | Description |
|---------|-------------|
| `report` | Render the engagement narrative in-terminal |

The report shows:
- **Credential chain** — provenance tree of how each credential was obtained
- **Technique timeline** — chronological log of every technique run
- **Findings** — sorted by severity (critical → info)

**Details:** See [Report](./Report.md)

---

## Agent Commands

| Command | Description |
|---------|-------------|
| `ask <question>` | Ask the local RAG agent a question about the engagement |

**Details:** See [Agent Mode](./Agent-Mode.md)

> **Note:** `ask` requires the optional agent extra: `uv sync --extra agent`

---

## General Commands

| Command | Description |
|---------|-------------|
| `help` | Show the full command reference table |
| `exit` / `quit` | Exit QM |

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0-rc3 | 2026-08-07 | Corrected the Azure service-principal tenant flag and updated release metadata. |
| v1.0-rc2 | 2026-08-04 | Shell command reference aligned to the shipped public command set, including Entra acquire/export, playbooks, loot, activity, and CA bypass analysis |
