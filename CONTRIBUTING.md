# Contributing to Quantum Mechanic

Quantum Mechanic (QM) is a cross-cloud offensive security framework. Contributing a new technique means writing a Python module that teaches the tool a new attack primitive and documents it for both operators and defenders.

## License of Contributions

Unless explicitly agreed otherwise in writing, contributions submitted to
Quantum Mechanic are accepted for distribution under the repository's project
license: `AGPL-3.0-or-later`.

If you copy in third-party material, you are responsible for preserving its
license notice, attribution, and redistribution requirements.

---

## 🚀 Quick Start: Start from a Nearby Technique

The public repository does not ship the private scaffolding helpers. Start by
copying a nearby technique that matches your provider and tactic, then rename
it and adjust the metadata:

- `src/quantum_mechanic/techniques/<tactic>/<name>.py`
- `tests/unit/techniques/<tactic>/test_<name>.py`

---

## 🛠 What Makes a Technique?

A technique is a standalone Python file containing three essential parts:

### 1. The Header (Documentation as Code)
Every module starts with a standardized block comment. This provides immediate context for operators and detection guidance for blue teams.

```python
# ================================================================
# TECHNIQUE: tactic/name
# PURPOSE:   What this attack achieves.
# PROVIDERS: aws, azure, gcp, oci
# HOW IT WORKS: Technical summary of the API calls used.
# DETECTION: Guidance for defenders (CloudTrail, Activity Logs).
# SAFE:      Yes/No (Read-only vs. State-changing)
# ================================================================
```

### 2. The `@technique` Decorator
The decorator registers your module with the QM harness. It supports a **Declarative Schema** (`loot_schema`) so you don't have to write custom table rendering code.

```python
LOOT_SCHEMA = [
    ('id',    'Resource ID', 'bold cyan'),
    ('state', 'Status',      'green'),
]

@technique(
    technique_id="discovery/my_module",
    tactic="discovery",
    providers=["aws"],
    loot_schema=LOOT_SCHEMA,
    loot_items_key="items"
)
def execute(ctx: ExecutionContext):
    # Your logic here
    return {"items": [{"id": "res-1", "state": "active"}]}
```

### 3. The `execute(ctx)` Function
This is where your attack logic lives. You use the `ctx` object to interact with the cloud, log findings, and save evidence. **Never call cloud SDKs directly; always use the `ctx` abstractions.**

---

## ✅ Quality Gates

Before opening a Pull Request, ensure your module passes these checks:

1. **Unit Tests**: Place tests in `tests/unit/techniques/`. Mock all cloud responses.
2. **Public validation**: Run `uv run pytest tests/unit/ -q` or `make test`
3. **Safety**: If your module changes state (creates/deletes resources), it **must** be marked `safe=False`.
4. **Coverage**: Add focused tests for the code you changed. The repository's
   broader coverage gate is maintained separately from this quick-start path.

---

## 🤝 Module Parity Principle

QM aims for four-cloud coverage. If you implement a technique for one cloud (e.g., AWS), consider if an analogous service exists on Azure, GCP, or OCI. We prefer modules that follow universal cloud patterns over provider-specific quirks.

**Questions?** Check the internal `docs/` directory or join our development discussions.
