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

import enum
import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class ParameterType(enum.StrEnum):
    """Supported data types for technique parameters."""
    STRING  = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST    = "list"

    @property
    def label(self) -> str:
        """Operational label for display."""
        return {
            ParameterType.STRING:  "Text",
            ParameterType.INTEGER: "Number",
            ParameterType.BOOLEAN: "Toggle",
            ParameterType.LIST:    "List",
        }.get(self, "Unknown")


@dataclass(frozen=True)
class Parameter:
    """Definition of a single technique parameter."""
    name: str
    description: str
    required: bool = False
    default: Any = None
    type: ParameterType = ParameterType.STRING
    choices: list[Any] | None = None
    example: str | None = None


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
    formatter_func: Callable | None = None  # Function to render rich output in shell
    loot_schema: list[tuple[str, str | None, str | None]] | None = None  # Declarative table schema
    loot_items_key: str | None = None  # Key in result data containing the list of items
    parameters: list[Parameter] = field(default_factory=list)

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
    formatter: Callable | None = None,
    loot_schema: list[tuple[str, str | None, str | None]] | None = None,
    loot_items_key: str | None = None,
    parameters: list[Parameter] | None = None,
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
        exploit_pack: Whether this belongs to the exploit pack.
        formatter: Optional function to render rich table output.
                   Signature: func(result: TechniqueResult) -> None
        loot_schema: Optional declarative schema for automatic table rendering.
                     List of (key, display_name, style) tuples.
        loot_items_key: Key in the returned dictionary that contains the list of
                        items to render (if the result isn't already a list).
    """
    # ----------------------------------------------------------------
    # Normalize tactic to consistent Title Case for display.
    # Technique authors may write 'discovery', 'Discovery',
    # 'Privilege Escalation', or 'privilege_escalation' — all map
    # to the same canonical display value ('Discovery',
    # 'Privilege Escalation', etc.).
    # ----------------------------------------------------------------
    normalized_tactic = " ".join(
        word.capitalize() for word in tactic.replace("_", " ").split()
    )

    metadata = TechniqueMetadata(
        id=technique_id,
        tactic=normalized_tactic,
        providers=providers,
        severity=severity,
        mitre_id=mitre_id,
        safe=safe,
        description=description,
        safe_mode_available=safe_mode_available,
        exploit_pack=exploit_pack,
        formatter_func=formatter,
        loot_schema=loot_schema,
        loot_items_key=loot_items_key,
        parameters=parameters or [],
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        wrapper.__technique__ = metadata  # type: ignore[attr-defined]
        return wrapper

    return decorator
