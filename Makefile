# Quantum Mechanic — Makefile
.PHONY: test boundary integration smoke smoke-aws smoke-azure smoke-entra smoke-gcp smoke-oci e2e-check e2e e2e-all e2e-connect public-build public-preview public-verify public-stage-local clean quality quality-fix

SANDBOX ?= assume_role_chain_aws
PUBLIC_OUT ?= /private/tmp/qm-public-release
PUBLIC_PREVIEW_DIR ?= /private/tmp/qm-public-preview
PUBLIC_LOCAL_REPO ?= ../quantum_mechanic

# ----------------------------------------------------------------
# Public/private boundary check (required before unit tests)
# ----------------------------------------------------------------
boundary:
	uv run python tools/check-public-boundary.py

# ----------------------------------------------------------------
# Public release validation
# ----------------------------------------------------------------
public-build: boundary
	env UV_CACHE_DIR=/private/tmp/uv-cache scripts/build-public.sh --out $(PUBLIC_OUT)

public-preview:
	env UV_CACHE_DIR=/private/tmp/uv-cache scripts/build-public-preview.sh --dir=$(PUBLIC_PREVIEW_DIR)

public-verify: boundary
	env UV_CACHE_DIR=/private/tmp/uv-cache scripts/build-public.sh --out $(PUBLIC_OUT)
	env UV_CACHE_DIR=/private/tmp/uv-cache scripts/build-public-preview.sh --no-test --dir=$(PUBLIC_PREVIEW_DIR)
	cd $(PUBLIC_PREVIEW_DIR) && uv venv --quiet
	cd $(PUBLIC_PREVIEW_DIR) && env UV_CACHE_DIR=/private/tmp/uv-cache uv pip install --group dev -e . --quiet
	cd $(PUBLIC_PREVIEW_DIR) && env PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ./.venv/bin/python -m pytest tests/unit/ -q --basetemp .pytest_tmp -p no:unraisableexception
	cd $(PUBLIC_PREVIEW_DIR) && env QM_HOME=/private/tmp/qm-home-preview QM_WORKSPACE_DIR=/private/tmp/qm-work-preview ./.venv/bin/qm workspace list

public-stage-local: boundary
	env UV_CACHE_DIR=/private/tmp/uv-cache scripts/stage-public-local.sh --target "$(PUBLIC_LOCAL_REPO)"

# ----------------------------------------------------------------
# Unit tests (always safe, no AWS)
# ----------------------------------------------------------------
test: boundary
	uv run pytest tests/unit/ -q

# ----------------------------------------------------------------
# Shell integration tests — pexpect (no AWS, no network)
# ----------------------------------------------------------------
integration:
	uv run pytest tests/integration/ -q -m integration

# ----------------------------------------------------------------
# Smoke tests — canary against LIVE provider APIs.
#
# Runs a small battery of discovery techniques (whoami,
# enum_permissions, etc.) against real credentials pulled from the
# environment. Purpose: "did anything obvious break?" per-provider,
# ahead of a release.
#
# Reads credentials in this order per provider (first hit wins):
#   AWS:   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION
#          QM_CHAOS_AWS_ACCESS_KEY_ID / ...
#   Azure: AZURE_CLIENT_ID / _SECRET / _TENANT_ID / SUBSCRIPTION_ID
#          ARM_CLIENT_ID / ... (Terraform naming)
#          QM_CHAOS_AZURE_...
#   GCP:   GOOGLE_APPLICATION_CREDENTIALS + GCP_PROJECT_ID
#   OCI:   OCI_USER_OCID / _FINGERPRINT / _TENANCY_OCID / _KEY_FILE / _REGION
#   Entra: QM_ENTRA_ACCESS_TOKEN + QM_ENTRA_TENANT_ID
#
# If a provider's creds are missing, tests for that provider are
# skipped (not failed). Suitable for a `make smoke` run right before
# cutting a release tag.
# ----------------------------------------------------------------
smoke:
	uv run pytest tests/smoke/ -v

smoke-aws:
	uv run pytest tests/smoke/test_aws_techniques.py -v

smoke-azure:
	uv run pytest tests/smoke/test_azure_techniques.py -v

smoke-entra:
	uv run pytest tests/smoke/test_entra_techniques.py -v

smoke-gcp:
	uv run pytest tests/smoke/test_gcp_techniques.py -v

smoke-oci:
	uv run pytest tests/smoke/test_oci_techniques.py -v

# ----------------------------------------------------------------
