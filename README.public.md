# Quantum Mechanic

One shell for cloud offense across AWS, Azure, Entra ID, GCP, and OCI.

QM replaces the five-tab, six-tool sprawl of a typical cloud assessment. Import a credential, confirm your identity, enumerate what you can reach, escalate where the permissions let you, move laterally when they don't, and generate a finding-grade report at the end. Every API call is logged, every credential chain is tracked, and the evidence pipeline runs whether you remember to save things or not.

Current release: **v1.0.0** (2026-09-14).

## Authorized Use

QM is built for authorized security assessments, lab environments, and
sanctioned red team operations. You are responsible for having documented
permission before pointing it at anything. Comply with applicable law,
your engagement contract, and the rules of the systems you test.

## Quick Start

```bash
# Install
uv sync
uv run qm

# Create an engagement workspace
qm> workspace create acme-assessment

# Import credentials (pick your provider)
qm[acme-assessment]> import aws --profile pentester
# or: import azure --default
# or: import gcp --default
# or: import oci --profile DEFAULT
# or: acquire entra interactive

# Confirm identity
qm[acme-assessment][aws:pentester]> run discovery/whoami

# See what's available
qm[acme-assessment][aws:pentester]> techniques

# Run a first discovery pass
qm[acme-assessment][aws:pentester]> run discovery/enum_iam
qm[acme-assessment][aws:pentester]> run discovery/enum_compute

# Generate the engagement report
qm[acme-assessment][aws:pentester]> report
```

## What You Get

**Discovery.** Enumerate IAM principals, compute instances, storage buckets, secrets, serverless functions, and permissions from one prompt. Findings land in the workspace database, not in your terminal scrollback.

**Privilege Escalation.** Follow role assumption chains, abuse overpermissioned compute identities, and impersonate service accounts. QM tracks each hop so your report shows the full path.

**Lateral Movement.** Pivot between accounts, subscriptions, and identity providers using the trust relationships you discover. Cross-cloud pivots (Entra to ARM, for example) are first-class.

**Evidence and Reporting.** Every technique logs API calls, duration, and result status into the workspace. `report` renders a credential chain tree, technique timeline, and findings table inline. No post-processing needed.

## Supported Providers

| Provider | Auth Methods |
|----------|-------------|
| AWS | Named profiles, access keys, STS sessions |
| Azure | CLI sessions, service principals |
| Entra ID | Interactive/device-code OAuth, token import, browser CDP session import, FOCI expansion |
| GCP | Application default credentials, service account keys |
| OCI | Config file profiles |

## Agent Mode

For automation and CI/CD integration, QM exposes a headless JSON interface:

```bash
uv run qm --agent capabilities
uv run qm --agent --workspace acme-assessment run discovery/whoami
```

If you want the optional `ask` command and local RAG features:

```bash
uv sync --extra agent
```

The `agent` extra pulls in local ML dependencies. Not needed for the shell or JSON interface.

## Operator Flow

```
workspace create/load
  -> import or acquire credentials
  -> discovery/whoami (always run this first)
  -> discovery modules (enum_iam, enum_compute, enum_storage, ...)
  -> validate permissions and identities
  -> escalation / lateral movement as the permissions allow
  -> collect loot and evidence
  -> report
```

## Documentation

Full operator wiki in [docs/](docs/):

- [Getting Started](docs/wiki/Getting-Started.md)
- [Shell Reference](docs/wiki/Shell-Reference.md)
- [Credentials](docs/wiki/Credentials.md)
- [Techniques](docs/wiki/Techniques.md)
- [Evidence](docs/wiki/Evidence.md)
- [Agent Mode](docs/wiki/Agent-Mode.md)

## Tests

```bash
uv run pytest tests/unit/ -q     # unit tests
make test                         # public test target
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AGPL-3.0-or-later. See [LICENSE.md](LICENSE.md) and [docs/wiki/License.md](docs/wiki/License.md).
