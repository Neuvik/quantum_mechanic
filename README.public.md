# Quantum Mechanic

A cross-cloud offensive security framework for the MITRE ATT&CK Cloud matrix.

QM gives you a single shell to run discovery, privilege escalation, and lateral movement techniques across AWS, Azure, GCP, and OCI — with structured evidence capture, credential chain tracking, and engagement reporting built in.

## Quick Start

```bash
# Install dependencies
uv sync

# Launch the shell
uv run qm

# Create a workspace, import credentials, and go
qm> workspace create acme-assessment
qm[acme-assessment]> import aws --profile pentester
qm[acme-assessment][aws:pentester]> techniques
qm[acme-assessment][aws:pentester]> run discovery/whoami
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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new technique.

## Tests

```bash
uv run pytest tests/unit/ -q     # unit tests
make integration                  # shell integration tests
```

## License

MIT
