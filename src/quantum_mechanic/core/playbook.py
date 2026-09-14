# ================================================================
# MODULE: quantum_mechanic.core.playbook
# ----------------------------------------------------------------
# PURPOSE:   Orchestration engine for technique playbooks.
#            Loads YAML-defined sequences and executes them.
# ================================================================

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from quantum_mechanic.core.runner import TechniqueResult, TechniqueRunner
    from quantum_mechanic.core.telemetry import TelemetryEvent

logger = logging.getLogger(__name__)


class PlaybookRunner:
    """Loads and executes multi-step technique sequences."""

    def __init__(
        self, runner: TechniqueRunner, on_event: Callable[[TelemetryEvent], None] | None = None
    ):
        self.runner = runner
        self.on_event = on_event

    def run_file(self, playbook_path: Path) -> list[TechniqueResult]:
        """Load a playbook from YAML and execute all steps."""
        if not playbook_path.exists():
            raise FileNotFoundError(f"Playbook not found: {playbook_path}")

        with playbook_path.open("r") as f:
            # Load the first document from the stream
            data = next(yaml.safe_load_all(f))

        return self.run(data)

    def run(self, playbook_data: dict[str, Any]) -> list[TechniqueResult]:
        """Execute a playbook dictionary."""
        name = playbook_data.get("name", "Unnamed Playbook")
        steps = playbook_data.get("steps", [])
        results = []

        logger.info("Starting playbook: %s (%d steps)", name, len(steps))

        for i, step in enumerate(steps):
            step_name = step.get("name", f"Step {i + 1}")
            tech_id = step.get("technique")
            params = step.get("params", {})
            note = step.get("note")

            # Merge global run note
            if note:
                params["_run_note"] = note

            # --------------------------------------------------------
            # Explicitly emit a log event so the UI/Shell knows
            # we are starting a new playbook step.
            # --------------------------------------------------------
            if self.on_event:
                from quantum_mechanic.core.telemetry import (
                    TelemetryEvent,
                    TelemetryLevel,
                    TelemetryType,
                )

                self.on_event(
                    TelemetryEvent(
                        technique_id=tech_id,
                        event_type=TelemetryType.LOG,
                        level=TelemetryLevel.INFO,
                        message=f"Playbook Step: {step_name} [{tech_id}]",
                    )
                )

            logger.info("Executing step: %s [%s]", step_name, tech_id)

            try:
                result = self.runner.run(tech_id, params=params, on_event=self.on_event)
                results.append(result)

                if result.status == "error" and not step.get("continue_on_failure", False):
                    logger.error("Playbook halted: step '%s' failed.", step_name)
                    break
            except Exception as e:
                logger.error("Playbook error in step '%s': %s", step_name, e)
                if not step.get("continue_on_failure", False):
                    break

        return results
