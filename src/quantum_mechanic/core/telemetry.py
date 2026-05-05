# ================================================================
# MODULE: quantum_mechanic.core.telemetry
# ----------------------------------------------------------------
# PURPOSE:   Standardized telemetry events for technique execution.
#            Provides a unified model for real-time activity feeds.
#
# DESIGN:    Events are emitted by ExecutionContext and consumed
#            by the Transport layer (to display in shell or push
#            to the qmd SSE bus).
# ================================================================

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


class TelemetryType(enum.StrEnum):
    """Canonical event types for the telemetry bus."""
    TASK_START = "task_start"
    TASK_END   = "task_end"
    LOG        = "log"
    API_CALL   = "api_call"
    DISCOVERY  = "discovery"
    FINDING    = "finding"
    ERROR      = "error"


class TelemetryLevel(enum.StrEnum):
    """Log levels for telemetry messages."""
    DEBUG   = "debug"
    INFO    = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR   = "error"


@dataclass(frozen=True)
class TelemetryEvent:
    """A single structured event from the framework."""
    technique_id: str
    event_type: TelemetryType
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    level: TelemetryLevel = TelemetryLevel.INFO
    message: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON for the wire."""
        return json.dumps(asdict(self))
