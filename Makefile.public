# Quantum Mechanic — Public Makefile
.PHONY: help test shell-smoke

help:
	@echo "Available targets:"
	@echo "  make test        - run the public unit test suite"
	@echo "  make shell-smoke - boot the public shell and list workspaces"

test:
	uv run pytest tests/unit/ -q

shell-smoke:
	env QM_HOME=/tmp/qm-home QM_WORKSPACE_DIR=/tmp/qm-work uv run qm workspace list
