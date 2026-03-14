# ================================================================
# MODULE: quantum_mechanic.core.technique
# ----------------------------------------------------------------
# PURPOSE:   The @technique decorator. Applied to functions that
#            implement attack techniques. Stores metadata (ATT&CK
#            mapping, provider support, severity) on the function
#            for the module loader to discover.
#
# USAGE:
#   @technique(
#       id="discovery/whoami",
#       tactic="discovery",
#       providers=["aws", "azure"],
#       severity="info",
#       safe=True,
#   )
#   def execute(ctx):
#       ...
# ================================================================

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TechniqueMetadata:
    """Metadata attached to a technique function by the decorator.

    This is what the module loader reads to build the technique
    registry and what the shell/agent mode uses to display info.
    """

    id: str  # Unique ID ("discovery/whoami")
    tactic: str  # ATT&CK tactic ("discovery")
    providers: list[str]  # Supported providers (["aws", "azure"])
    severity: str = "info"  # Severity level
    mitre_id: str | None = None  # ATT&CK technique ID ("T1087")
    safe: bool = True  # Is this read-only / non-destructive?
    description: str = ""  # One-line description
    safe_mode_available: bool = False  # Can this run in check-only mode?
    exploit_pack: bool = False  # Hidden from main menu; use 'exploits' submenu

def technique(
    *,
    technique_id: str,
    tactic: str,
    providers: list[str],
    severity: str = "info",
    mitre_id: str | None = None,
    safe: bool = True,
    description: str = "",
    safe_mode_available: bool = False,
    exploit_pack: bool = False,
) -> Callable:
    """Decorator that marks a function as a QM technique.

    The decorated function must accept a single `ctx` argument
    (the execution context). The decorator attaches a
    TechniqueMetadata instance to the function as `__technique__`.

    Args:
        technique_id: Unique technique identifier (e.g., "discovery/whoami").
        tactic: MITRE ATT&CK tactic name.
        providers: List of supported cloud providers.
        severity: Finding severity level.
        mitre_id: MITRE ATT&CK technique ID.
        safe: Whether this technique is non-destructive.
        description: One-line description.
        safe_mode_available: Whether check-only mode is supported.

    Returns:
        Decorated function with __technique__ attribute.
    """
    metadata = TechniqueMetadata(
        id=technique_id,
        tactic=tactic,
        providers=providers,
        severity=severity,
        mitre_id=mitre_id,
        safe=safe,
        description=description,
        safe_mode_available=safe_mode_available,
        exploit_pack=exploit_pack,
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        wrapper.__technique__ = metadata  # type: ignore[attr-defined]
        return wrapper

    return decorator
