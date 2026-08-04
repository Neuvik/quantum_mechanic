# Release Notes

| | |
|---|---|
| **Version** | v1.0-rc2 |
| **Issued** | 2026-08-04 |
| **Last reviewed** | 2026-08-04 |
| **Status** | Active |

---

## v1.0-rc2 — 2026-08-04

Public release candidate.

### What ships in this release

- Interactive `qm` shell
- Headless `qm --agent` JSON mode
- Workspace management
- Credential import and activation across AWS, Azure, Entra, GCP, and OCI
- Discovery, collection, escalation, lateral movement, exfiltration, and persistence techniques within the public release boundary
- Evidence capture and inline `report`
- Optional local RAG support through the `agent` extra

### Public release notes

- The public repository now ships a dedicated public `Makefile` and
  `.gitignore` instead of trimmed private artifacts.
- The optional `ask`/RAG stack has been separated from the base install.
  Run `uv sync --extra agent` only if you want local agent features.
- Public docs now describe Entra explicitly as a first-class surface.
- Public docs were aligned with the actual shipped command set and current
  version number.

### Install

```bash
uv sync
uv run qm
```

Optional local RAG support:

```bash
uv sync --extra agent
```

---

## Change Log

| Rev | Date | Change |
|-----|------|--------|
| v1.0-rc2 | 2026-08-04 | Public release-candidate documentation and packaging aligned to the shipped command set and optional agent extra |
