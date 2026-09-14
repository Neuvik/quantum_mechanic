# Agent Mode

| | |
|---|---|
| **Version** | v1.0.0 |
| **Issued** | 2026-09-14 |
| **Last reviewed** | 2026-09-14 |
| **Status** | Active |

Quantum Mechanic supports AI agents in two distinct ways:
1. **Interactive RAG Agent** (`ask` command in the shell)
2. **Non-Interactive JSON API** (`qm --agent` from the terminal)

---

## 1. Interactive RAG Agent (`ask`)

The `ask` command gives you a local RAG (Retrieval-Augmented Generation) agent that can answer questions about the current engagement and suggest next steps.

### Requirements
Agent mode requires the `[agent]` optional extras:
```bash
uv sync --extra agent
```
*(This installs the optional local-RAG dependencies. It is not required to use
the rest of QM.)*

### Usage
```
qm[acme-assessment][aws:1]> ask what escalation paths do I have from the current credential?
```

The agent:
1. Retrieves context from the current workspace (credentials, findings, resources)
2. Reasons over what has been discovered so far
3. Suggests techniques to run or attack paths to pursue

### Limitations in v1.0.0
- The agent answers based on what has already been discovered in the workspace. It does not autonomously run techniques.
- Autonomous engagement orchestration is not part of the public `v1.0.0`
  release.

---

## 2. Non-Interactive JSON API (`qm --agent`)

The `qm --agent` CLI flag provides a headless, machine-readable JSON interface designed for consumption by autonomous LLM coding agents (like Claude Code or Antigravity).

It outputs compact JSON to `stdout` and logs strictly to `stderr`, never blocking for input.

### Agent Commands

| Command | Action | Output |
|---------|--------|--------|
| `qm --agent capabilities` | Dump framework capabilities | Providers, techniques, credentials, workspace |
| `qm --agent workspace list` | List workspaces | Array of workspace names |
| `qm --agent workspace create <name>` | Create a workspace | Success confirmation |
| `qm --agent import aws --profile <n> --workspace <w>` | Import credential | Credential ID and details |
| `qm --agent creds --workspace <w>` | List credentials | Array of credential metadata |
| `qm --agent run <id> --workspace <w>` | Run a technique (uses active cred) | Compact `AgentSummary` JSON |
| `qm --agent run <id> --workspace <w> --credential <c>` | Run using specific cred | Compact `AgentSummary` JSON |
| `qm --agent run <id> --raw ...` | Run a technique | Full, unabridged original result JSON |

### AgentSummary Format
When a technique runs (without `--raw`), the output is wrapped in a token-efficient JSON envelope containing the execution status, tactic, duration, API calls made, and key data points. Full evidence is always written to disk (see [Evidence](./Evidence.md)).

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0.0 | 2026-09-14 | General availability release. |
| v1.0-rc3 | 2026-08-07 | Updated release metadata for the rc3 package. |
| v1.0-rc2 | 2026-08-04 | Public release candidate documentation aligned to the shipped optional `agent` extra and `qm --agent` interface |
