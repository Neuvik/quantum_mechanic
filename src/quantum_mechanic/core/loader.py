# ================================================================
# MODULE: quantum_mechanic.core.loader
# ----------------------------------------------------------------
# PURPOSE:   Module discovery and technique registry. Scans the
#            techniques/ directory for Python files, imports them,
#            and extracts functions decorated with @technique.
#
# DESIGN:    The loader builds a registry of all available
#            techniques at startup. The shell and agent mode use
#            this registry to list, validate, and execute techniques.
# ================================================================

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from quantum_mechanic.core.technique import TechniqueMetadata

logger = logging.getLogger(__name__)


@dataclass
class RegisteredTechnique:
    """A discovered technique with its metadata and callable."""

    metadata: TechniqueMetadata
    function: Callable
    module_path: str  # e.g., "quantum_mechanic.techniques.discovery.whoami"


class TechniqueLoader:
    """Discovers and loads technique modules.

    Scans the techniques package for @technique-decorated functions
    and builds a registry for lookup by ID.
    """

    def __init__(self) -> None:
        self._techniques: dict[str, RegisteredTechnique] = {}

    def load_all(self) -> int:
        """Discover and load all techniques from the techniques package.

        Returns:
            Number of techniques loaded.
        """
        try:
            import quantum_mechanic.techniques as techniques_pkg
        except ImportError:
            logger.warning("No techniques package found")
            return 0

        count = 0
        package_path = techniques_pkg.__path__
        prefix = techniques_pkg.__name__ + "."

        # --------------------------------------------------------
        # Walk the techniques package recursively, importing each
        # module and checking for @technique-decorated functions.
        # --------------------------------------------------------
        for _importer, modname, ispkg in pkgutil.walk_packages(package_path, prefix=prefix):
            if ispkg:
                # --------------------------------------------------------
                # Import subpackages (e.g., techniques.discovery) to
                # ensure their __init__.py runs, but don't look for
                # techniques in __init__ files.
                # --------------------------------------------------------
                try:
                    importlib.import_module(modname)
                except Exception as e:
                    logger.warning("Failed to import package %s: %s", modname, e)
                continue

            try:
                module = importlib.import_module(modname)
            except Exception as e:
                logger.warning("Failed to import module %s: %s", modname, e)
                continue

            # --------------------------------------------------------
            # Find all functions with a __technique__ attribute
            # (set by the @technique decorator).
            # --------------------------------------------------------
            for _name, obj in inspect.getmembers(module, inspect.isfunction):
                technique_meta = getattr(obj, "__technique__", None)
                if technique_meta is not None and isinstance(technique_meta, TechniqueMetadata):
                    registered = RegisteredTechnique(
                        metadata=technique_meta,
                        function=obj,
                        module_path=modname,
                    )
                    self._techniques[technique_meta.id] = registered
                    count += 1
                    logger.debug(
                        "Loaded technique: %s from %s",
                        technique_meta.id,
                        modname,
                    )

        return count

    def reload_all(self) -> int:
        """Hot-reload all technique modules and re-scan for @technique decorators.

        Uses importlib.reload() on any already-imported technique module so
        changes to .py files are picked up without restarting qm.

        Returns:
            Number of techniques loaded after the reload.
        """
        import sys
        # Reload any technique module that is already in sys.modules.
        for modname in list(sys.modules):
            if modname.startswith("quantum_mechanic.techniques."):
                try:
                    importlib.reload(sys.modules[modname])
                except Exception as e:
                    logger.warning("Reload failed for %s: %s", modname, e)

        # Clear the registry and re-scan.
        self._techniques.clear()
        return self.load_all()

    def get(self, technique_id: str) -> RegisteredTechnique | None:
        """Get a registered technique by ID."""
        return self._techniques.get(technique_id)

    def list_all(self) -> list[RegisteredTechnique]:
        """List non-exploit techniques, sorted by ID.

        Exploit pack techniques (exploit_pack=True) are intentionally
        excluded — they appear only via list_exploits() to keep the
        main techniques menu focused on cloud/post-auth workflows.
        """
        return sorted(
            [t for t in self._techniques.values() if not t.metadata.exploit_pack],
            key=lambda t: t.metadata.id,
        )

    def list_exploits(self) -> list[RegisteredTechnique]:
        """List only exploit pack techniques (exploit_pack=True), sorted by ID.

        These are surfaced via the dedicated 'exploits' shell submenu
        and kept separate from the main techniques workflow.
        """
        return sorted(
            [t for t in self._techniques.values() if t.metadata.exploit_pack],
            key=lambda t: t.metadata.id,
        )

    def list_by_tactic(self, tactic: str) -> list[RegisteredTechnique]:
        """List techniques filtered by ATT&CK tactic."""
        return [t for t in self._techniques.values() if t.metadata.tactic == tactic]

    def list_by_provider(self, provider: str) -> list[RegisteredTechnique]:
        """List techniques that support a given provider."""
        return [t for t in self._techniques.values() if provider in t.metadata.providers]
