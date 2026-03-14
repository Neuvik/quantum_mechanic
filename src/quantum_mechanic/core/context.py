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

import json
import logging
import time
from typing import Any

from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import AuthProvider, WhoAmIResult

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.workspace = workspace
        self.credential_id = credential_id
        self.provider = provider
        self.session = session
        self.technique_id = technique_id
        self.safe_mode = safe_mode
        self.params: dict[str, Any] = params or {}
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

    def log(self, message: str) -> None:
        """Log a message for the operator (displays in shell)."""
        logger.info("[%s] %s", self.technique_id or "qm", message)
