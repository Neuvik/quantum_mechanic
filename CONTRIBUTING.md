# Contributing to Quantum Mechanic

Quantum Mechanic (QM) is a cross-cloud offensive security framework. Contributing a new technique means writing a Python module that teaches the tool a new attack primitive and documents it for both operators and defenders.

---

## 🚀 Quick Start: Scaffold Your Technique

Don't start from a blank file. Use our YAML-to-technique generator to produce the boilerplate, decorator, and test file automatically:

```bash
# 1. Define your technique in a YAML file (use scripts/technique_defs/ as a guide)
# 2. Run the generator
uv run scripts/gen_technique.py my_new_technique.yaml
```

The generator creates:
- `src/quantum_mechanic/techniques/<tactic>/<name>.py` — Source with stubs
- `tests/unit/techniques/<tactic>/test_<name>.py` — Unit test scaffold

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
2. **Formatting**: Run `uv run ruff check .`
3. **Safety**: If your module changes state (creates/deletes resources), it **must** be marked `safe=False`.
4. **Coverage**: Target ≥80% code coverage for your new module.

---

## 🤝 Module Parity Principle

QM aims for four-cloud coverage. If you implement a technique for one cloud (e.g., AWS), consider if an analogous service exists on Azure, GCP, or OCI. We prefer modules that follow universal cloud patterns over provider-specific quirks.

**Questions?** Check the internal `docs/` directory or join our development discussions.
