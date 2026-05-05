# ================================================================
# MODULE: quantum_mechanic.core.context
# ----------------------------------------------------------------
# PURPOSE:   The execution context (ctx) passed to every technique.
#            Wraps the workspace, active credential, provider, and
#            evidence logging so technique authors don't touch
#            infrastructure directly.
#
# DESIGN:    Techniques call ctx.whoami(), ctx.workspace.add_xxx(),
#            etc. The context handles credential resolution,
#            API call logging, and provider routing automatically.
# ================================================================

from __future__ import annotations

import contextlib
import json
import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

from quantum_mechanic.core.telemetry import TelemetryEvent, TelemetryLevel, TelemetryType
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)

# Callback signature for real-time telemetry streaming.
EventCallback = Callable[[TelemetryEvent], None]


class ExecutionContext:
    """Execution context for technique functions.

    Every technique receives this as its only argument. It provides
    access to the workspace, the active provider, and evidence
    logging. All API calls are automatically recorded.
    """

    def __init__(
        self,
        workspace: Workspace,
        credential_id: int,
        provider: AuthProvider,
        session: Any,
        *,
        technique_id: str | None = None,
        safe_mode: bool = False,
        params: dict[str, Any] | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        self.workspace = workspace
        self.credential_id = credential_id
        self.provider = provider
        self.session = session
        self.technique_id = technique_id
        self.safe_mode = safe_mode
        self.params: dict[str, Any] = params or {}
        self._on_event = on_event
        self._provider_name = provider.provider_name
        self._api_call_count = 0

    @property
    def provider_name(self) -> str:
        """The name of the active cloud provider."""
        return self._provider_name

    @property
    def api_call_count(self) -> int:
        """Number of API calls made during this execution."""
        return self._api_call_count

    def get_param(self, name: str, default: Any | None = None) -> Any:
        """Retrieve a parameter value with an optional default.

        This is the preferred way for techniques to access their inputs.
        """
        return self.params.get(name, default)

    @contextlib.contextmanager
    def subtask(self, name: str, params: dict[str, Any] | None = None) -> Iterator[ExecutionContext]:
        """A context manager for running a logical subtask or child technique.

        Creates a temporary context with merged parameters and tracks it
        as a sub-operation for telemetry.
        """
        # Merge params (child overrides parent)
        merged_params = self.params.copy()
        if params:
            merged_params.update(params)

        # Create temporary child context
        sub_ctx = ExecutionContext(
            workspace=self.workspace,
            credential_id=self.credential_id,
            provider=self.provider,
            session=self.session,
            technique_id=f"{self.technique_id}/{name}",
            safe_mode=self.safe_mode,
            params=merged_params,
            on_event=self._on_event
        )

        # Link API call counter so child calls count toward parent total
        # (This assumes the child will increment sub_ctx._api_call_count)
        # However, a better way is to wrap the increment logic.

        self.info(f"Subtask started: {name}")
        try:
            yield sub_ctx
        finally:
            # Sync API call count back to parent
            self._api_call_count += sub_ctx._api_call_count
            self.info(f"Subtask completed: {name}")

    # ================================================================
    # Telemetry methods
    # ================================================================

    def _emit(self, event: TelemetryEvent) -> None:
        """Send an event to the registered callback, if any."""
        if self._on_event:
            try:
                self._on_event(event)
            except Exception as e:
                logger.debug("Telemetry callback failed: %s", e)

    def info(self, message: str, data: dict[str, Any] | None = None) -> None:
        """Log an informational message."""
        self.log(message)  # Fallback to standard logging
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.LOG,
            level=TelemetryLevel.INFO,
            message=message,
            data=data or {}
        ))

    def success(self, message: str, data: dict[str, Any] | None = None) -> None:
        """Log a successful operation or discovery."""
        self.log(f"SUCCESS: {message}")
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.LOG,
            level=TelemetryLevel.SUCCESS,
            message=message,
            data=data or {}
        ))

    def warn(self, message: str, data: dict[str, Any] | None = None) -> None:
        """Log a warning (e.g. permission denied on a non-critical path)."""
        self.log(f"WARNING: {message}")
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.LOG,
            level=TelemetryLevel.WARNING,
            message=message,
            data=data or {}
        ))

    def error(self, message: str, data: dict[str, Any] | None = None) -> None:
        """Log an error within the technique context."""
        self.log(f"ERROR: {message}")
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.ERROR,
            level=TelemetryLevel.ERROR,
            message=message,
            data=data or {}
        ))

    def discovery(self, asset_type: str, asset_id: str, metadata: dict[str, Any] | None = None) -> None:
        """Emit a structured discovery event."""
        msg = f"Discovered {asset_type}: {asset_id}"
        self.log(msg)
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.DISCOVERY,
            message=msg,
            data={
                "asset_type": asset_type,
                "asset_id": asset_id,
                "metadata": metadata or {}
            }
        ))

    # ================================================================
    # Provider methods
    # ================================================================

    def whoami(self) -> WhoAmIResult:
        """Identify the current principal.

        Calls the provider's whoami(), logs the API call, and
        stores the discovered principal in the workspace.

        Returns:
            Normalized identity information.
        """
        start = time.monotonic()
        result = self.provider.whoami(self.session)
        duration_ms = int((time.monotonic() - start) * 1000)

        # --------------------------------------------------------
        # Log the API call in the workspace audit trail.
        # --------------------------------------------------------
        self._api_call_count += 1
        self.workspace.log_api_call(
            provider=self._provider_name,
            action="whoami",
            credential_id=self.credential_id,
            service="sts" if self._provider_name == "aws" else "identity",
            request_params=None,
            response_status=200,
            response_summary=f"Identity: {result.friendly_name}",
            technique_id=self.technique_id,
            duration_ms=duration_ms,
        )

        # Stream API call via telemetry
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.API_CALL,
            message=f"API: whoami ({self._provider_name})",
            data={
                "provider": self._provider_name,
                "action": "whoami",
                "duration_ms": duration_ms
            }
        ))

        # --------------------------------------------------------
        # Store the discovered principal in the workspace database.
        # --------------------------------------------------------
        from quantum_mechanic.core.workspace import Account, Principal

        # Store the account if not already known.
        self.workspace.add_account(
            Account(
                id=result.account_id,
                provider=self._provider_name,
                name=result.account_name,
                account_type="account" if self._provider_name == "aws" else "subscription",
            )
        )

        # Store the principal.
        self.workspace.add_principal(
            Principal(
                id=result.principal_id,
                provider=self._provider_name,
                account_id=result.account_id,
                principal_type=result.principal_type,
                friendly_name=result.friendly_name,
                raw_data=json.dumps(result.raw_response) if result.raw_response else None,
            )
        )

        # Link the credential to the principal.
        self.workspace.update_credential_principal(
            self.credential_id,
            result.principal_id,
            friendly_name=result.friendly_name,
        )

        return result

    def finding(
        self,
        title: str,
        severity: str,
        description: str = "",
        evidence: dict | str | None = None,
        recommendation: str | None = None,
        mitre_id: str | None = None,
        detection_log: str | None = None,
    ) -> int:
        """Record a security finding against the current workspace.

        Convenience wrapper around workspace.add_finding() so technique
        authors can call ctx.finding(...) directly without touching the
        workspace API.

        Args:
            title:          Short headline for the finding.
            severity:       'critical', 'high', 'medium', 'low', or 'info'.
            description:    Free-text details. Falls back to title if empty.
            evidence:       Dict or JSON string of supporting evidence.
            recommendation: Remediation advice (stored in description if given).
            mitre_id:       MITRE ATT&CK technique ID, e.g. 'T1069.003'.
            detection_log:  Detection hint (appended to description).

        Returns:
            ID of the newly created finding row.
        """
        import json as _json
        full_desc = description or title
        if recommendation:
            full_desc += f"\n\nRemediation: {recommendation}"
        if detection_log:
            full_desc += f"\n\nDetection: {detection_log}"

        ev_str: str
        if evidence is None:
            ev_str = "{}"
        elif isinstance(evidence, dict):
            ev_str = _json.dumps(evidence, default=str)
        else:
            ev_str = str(evidence)

        tactic = (self.technique_id or "").split("/")[0] if self.technique_id else "unknown"

        fid = self.workspace.add_finding(
            technique_id=self.technique_id or "unknown",
            tactic=tactic,
            title=title,
            severity=severity,
            provider=self._provider_name,
            description=full_desc,
            evidence=ev_str,
            mitre_id=mitre_id,
        )

        # Stream finding via telemetry
        self._emit(TelemetryEvent(
            technique_id=self.technique_id or "unknown",
            event_type=TelemetryType.FINDING,
            level=TelemetryLevel.WARNING if severity in ("low", "medium") else TelemetryLevel.ERROR,
            message=f"Finding: {title}",
            data={
                "id": fid,
                "severity": severity,
                "mitre_id": mitre_id
            }
        ))

        return fid

    def log(self, message: str) -> None:
        """Log a message for the operator (displays in shell)."""
        logger.info("[%s] %s", self.technique_id or "qm", message)
