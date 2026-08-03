# Quantum Mechanic

A cross-cloud offensive security framework for the MITRE ATT&CK Cloud matrix.

QM gives you a single shell to run discovery, privilege escalation, and lateral movement techniques across AWS, Azure, GCP, and OCI — with structured evidence capture, credential chain tracking, and engagement reporting built in.

## TL;DR

Install dependencies, launch the shell, create a workspace, import one credential, confirm identity, and enumerate techniques:

```bash
# 1. Install dependencies
uv sync

# 2. Launch the shell
uv run qm

# 3. Create a workspace
qm> workspace create acme-assessment

# 4. Import credentials for one provider
qm[acme-assessment]> import aws --profile pentester
# or: import azure --default
# or: import gcp --default
# or: import oci --profile DEFAULT
# or: acquire entra interactive

# 5. Confirm identity
qm[acme-assessment][aws:pentester]> run discovery/whoami

# 6. See what modules exist
qm[acme-assessment][aws:pentester]> techniques

# 7. Run a first discovery pass
qm[acme-assessment][aws:pentester]> run discovery/enum_iam
qm[acme-assessment][aws:pentester]> run discovery/enum_compute

# 8. Generate an operator-facing report when done
qm[acme-assessment][aws:pentester]> report
```

## Quick Start

QM is workspace-first.

1. Create or load a workspace for the assessment.
2. Import or acquire credentials for the cloud or identity provider you want to operate against.
3. Run `discovery/whoami` first so you know exactly which identity is active.
4. Use `techniques` and `info <technique-id>` to understand what is available before running higher-impact modules.
5. Use `report` and the workspace loot/evidence artifacts at the end of the run.

If you want a non-interactive JSON interface for automation:

```bash
uv run qm --agent capabilities
uv run qm --agent --workspace acme-assessment creds
uv run qm --agent --workspace acme-assessment run discovery/whoami
```

## Common Operator Flow

```text
workspace create/load
→ import or acquire credentials
→ run discovery/whoami
→ run discovery modules
→ validate interesting permissions or identities
→ run escalation/lateral movement modules as needed
→ collect loot/evidence
→ report
```

## What It Does

**Discovery** — Enumerate IAM principals, compute instances, storage, and permissions across four clouds from a single interface.

**Privilege Escalation** — Identify and exploit overpermissioned compute identities, role assumption chains, and service account impersonation paths.

**Lateral Movement** — Move between cloud accounts and subscriptions using discovered credentials and trust relationships.

**Evidence & Reporting** — Every API call is logged. Findings include severity ratings, detection signatures for defenders, and remediation guidance. Generate a narrative report at the end of an engagement.

## Supported Clouds

| Provider | Auth Methods | Status |
|----------|-------------|--------|
| AWS | Named profiles, access keys, STS sessions | Implemented |
| Azure | CLI sessions, service principals | Implemented |
| GCP | Application default credentials, service account keys | Implemented |
| OCI | Config file profiles | Implemented |

## Documentation

See the [docs/](docs/) folder for the operator wiki, including:

- [Getting Started](docs/wiki/Getting-Started.md)
- [Shell Reference](docs/wiki/Shell-Reference.md)
- [Techniques](docs/wiki/Techniques.md)
- [Agent Mode](docs/wiki/Agent-Mode.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new technique.

## Tests

```bash
uv run pytest tests/unit/ -q     # unit tests
make integration                  # shell integration tests
```

## License

Quantum Mechanic is licensed under the GNU Affero General Public License,
version 3 or later (`AGPL-3.0-or-later`).

- Full project notice: [LICENSE.md](LICENSE.md)
- Public license guide: [docs.public/wiki/License.md](docs.public/wiki/License.md)
