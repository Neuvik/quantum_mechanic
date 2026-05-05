# Shell Reference

| | |
|---|---|
| **Version** | v0.1.0 |
| **Issued** | 2026-03-09 |
| **Last reviewed** | 2026-03-12 |
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
| `import azure --client-id <id> --client-secret <s> --tenant <t>` | Import service principal |
| `import gcp --default` | Import GCP application default credentials |
| `import gcp --key-file <path>` | Import GCP service account key JSON |
| `import oci --default` | Import OCI config file (DEFAULT profile) |
| `import oci --profile <name>` | Import OCI named profile |
| `creds` | List all credentials with status |
| `creds --active` | List active credentials only |
| `creds delete <id>` | Remove credential by ID |
| `use <id>` | Set credential `<id>` as active |
| `raw <id>` | Show raw JSON for credential or principal `<id>` |

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

---

## General Commands

| Command | Description |
|---------|-------------|
| `help` | Show the full command reference table |
| `exit` / `quit` | Exit QM |
