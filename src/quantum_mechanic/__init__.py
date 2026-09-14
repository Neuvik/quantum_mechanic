# ================================================================
# MODULE: quantum_mechanic
# ----------------------------------------------------------------
# PURPOSE:   Package root for Quantum Mechanic — a cross-cloud
#            offensive security assessment framework.
#
# EXPORTS:   technique decorator, version string.
#            __version__ is sourced from installed package metadata
#            (pyproject.toml::version) rather than hardcoded, so the
#            banner, `qm --version`, and `qmd`'s web template all stay
#            in lockstep with the release tag automatically.
# ================================================================

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("quantum-mechanic")
except PackageNotFoundError:
    # Package isn't installed (running from a source checkout without
    # `uv sync` yet). Fall back to a dev marker so imports still work.
    __version__ = "0.0.0+unknown"
