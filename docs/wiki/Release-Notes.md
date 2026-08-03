# Release Notes

| | |
|---|---|
| **Issued** | 2026-03-09 |
| **Last reviewed** | 2026-03-12 |
| **Status** | Active |

---

## v0.1.0 — 2026-03-09

Initial release.

### Features

**Workspace Management**
- `workspace create <name>` — create a new engagement workspace
- `workspace load <name>` — open an existing workspace
- `workspace list` — list all workspaces on disk

**Credential Import**
- AWS: profile, access key
- Azure: default (CLI session), service principal
- GCP: application default, service account key file
- OCI: default config, named profile

**Credential Management**
- `creds` / `creds --active` — list credentials with lifecycle status
- `creds delete <id>` — remove a credential
- `use <id>` — switch active credential
- `raw <id>` — show raw JSON for any credential or principal

**Techniques**
- `techniques` — browse all loaded techniques filtered by active provider
- `run <id>` / `<id>` shortcut — execute a technique
- `run <id> --param k=v` — pass parameters
- `run <id> --safe` — safe-check mode (read-only validation)
- `help <id>` — inline technique documentation
- `reload` — hot-reload technique modules without restarting

**Techniques shipped:**
| ID | Tactic | Providers |
|----|--------|-----------|
| `discovery/whoami` | Discovery | AWS, Azure, GCP, OCI |
| `discovery/enum_iam` | Discovery | AWS, Azure, GCP, OCI |
| `escalation/assume_role_chain` | Privilege Escalation | AWS |
| `escalation/gcp_sa_token_creator` | Privilege Escalation | GCP |
| `lateral_movement/azure_run_command` | Lateral Movement | Azure |

**Engagement Report**
- `report` — inline engagement narrative showing credential chain, technique timeline, and findings sorted by severity

**RAG Agent**
- `ask <question>` — local RAG agent for engagement guidance

### Architecture
- Cross-cloud workspace database (SQLite, provider-agnostic schema)
- Four-layer test harness (unit → integration → Terraform → live)

---

## Upcoming (v0.2.0)

- Additional techniques: `discovery/enum_compute`, `escalation/compute_identity_abuse`
- Playbook system (YAML-defined technique sequences)
