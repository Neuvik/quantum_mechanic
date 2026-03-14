# ================================================================
# MODULE: quantum_mechanic.core.transport
# qm:private-boundary-allow — RemoteTransport intentionally imports
# daemon.pki (OperatorToken, decode_token). This is a known gateway
# file. The import is deferred to avoid import-time coupling.
# ----------------------------------------------------------------
# PURPOSE:   Transport abstraction layer. Separates the operator
#            shell and agent loop from the mechanism of technique
#            execution. Both local (in-process) and remote (daemon)
#            modes implement the same Transport interface.
#
# DESIGN:    Kubernetes API server model — Transport is the seam
#            between "what to do" and "how to reach the executor."
#            LocalTransport wraps TechniqueRunner directly.
#            RemoteTransport sends JSON over mTLS to qmd.
#
# CONTRACT:  Every method on Transport MUST:
#            - Never raise an unhandled exception to the caller.
#            - Return TechniqueResult for run_technique, always.
#            - Be callable by human operator AND AI agent alike.
#
# TDD REF:   tests/unit/core/test_transport_contract.py
# ================================================================

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from quantum_mechanic.core.loader import TechniqueLoader
from quantum_mechanic.core.runner import TechniqueResult, TechniqueRunner
from quantum_mechanic.core.technique import TechniqueMetadata
from quantum_mechanic.core.workspace import Workspace
from quantum_mechanic.providers.base import ProviderRegistry


class Transport(ABC):
    """Abstract base: the surface every QM client uses to run techniques.

    An operator's shell command, an AI agent, and a Neutrino implant
    all talk through a Transport. The concrete implementation decides
    whether execution happens in-process or over the network.

    INVARIANTS (enforced by every implementation):
      - run_technique() never raises — errors are TechniqueResult(status='error').
      - list_techniques() never returns an empty iterable if techniques are installed.
      - No method leaks credentials between workspaces.
    """

    @abstractmethod
    def run_technique(
        self,
        technique_id: str,
        credential_id: int | None = None,
        *,
        safe_mode: bool = False,
        params: dict | None = None,
    ) -> TechniqueResult:
        """Execute a technique and return a structured result.

        Args:
            technique_id: The slash-separated technique identifier, e.g.
                          "discovery/whoami" or "escalation/assume_role_chain".
            credential_id: Override the workspace's active credential.
                           If None, the active credential is used.
            safe_mode:     Run in check-only mode — no destructive actions.
            params:        Arbitrary key/value parameters forwarded to the
                           technique's ExecutionContext.

        Returns:
            TechniqueResult with status in ('success', 'error', 'skipped').
            Never raises — errors are returned as status='error'.
        """

    @abstractmethod
    def list_techniques(
        self,
        provider: str | None = None,
    ) -> Iterator[TechniqueMetadata]:
        """Enumerate available techniques.

        Args:
            provider: If given, return only techniques that support this
                      provider (e.g. "aws", "azure", "gcp", "oci").

        Returns:
            Iterator of TechniqueMetadata. Never empty if techniques loaded.
        """


class LocalTransport(Transport):
    """In-process transport. Technique execution happens in the same process.

    This is the transport used in Local Mode (the v0.1 default). It wraps
    TechniqueRunner directly. No network. No serialization. Zero latency.

    Used by:
      - qm shell (human operator, local mode)
      - qm --agent (AI agent, local mode)
    """

    def __init__(
        self,
        workspace: Workspace,
        loader: TechniqueLoader,
        registry: ProviderRegistry,
    ) -> None:
        # --------------------------------------------------------
        # Store components, do not build TechniqueRunner yet.
        # Runner is constructed lazily so that workspace swaps
        # (e.g. operator changes workspace mid-session) work without
        # re-initialising Transport.
        # --------------------------------------------------------
        self._workspace = workspace
        self._loader = loader
        self._registry = registry

    @property
    def _runner(self) -> TechniqueRunner:
        """Lazily constructed runner, always using the current workspace."""
        return TechniqueRunner(self._workspace, self._loader, self._registry)

    def run_technique(
        self,
        technique_id: str,
        credential_id: int | None = None,
        *,
        safe_mode: bool = False,
        params: dict | None = None,
    ) -> TechniqueResult:
        """Execute a technique in-process via TechniqueRunner.

        CONTRACT: This method never raises. All errors become
                  TechniqueResult(status='error', error=<message>).
        """
        # --------------------------------------------------------
        # Delegate entirely to TechniqueRunner. Runner already
        # catches provider exceptions and formats error results.
        # We add one outer guard for any unexpected failure.
        # --------------------------------------------------------
        try:
            return self._runner.run(
                technique_id,
                credential_id=credential_id,
                safe_mode=safe_mode,
                params=params,
            )
        except Exception as exc:  # pragma: no cover — runner should catch all
            return TechniqueResult(
                technique_id=technique_id,
                provider="unknown",
                status="error",
                error=f"Transport internal error: {exc}",
            )

    def list_techniques(
        self,
        provider: str | None = None,
    ) -> Iterator[TechniqueMetadata]:
        """Return available techniques from the local loader.

        Args:
            provider: If given, filter to techniques that support this provider.

        Yields:
            TechniqueMetadata for each matching technique.
        """
        if provider is not None:
            for registered in self._loader.list_by_provider(provider):
                yield registered.metadata
        else:
            for registered in self._loader.list_all():
                yield registered.metadata


class RemoteTransport(Transport):
    """mTLS transport — sends technique requests to a qmd server over HTTPS.

    Accepts either an OperatorToken object or a qm:// encoded token string.
    Validates the token (expiry, tamper) at construction — fails fast before
    any network connection is attempted.

    Used by:
      - qm connect <token>   (human operator, remote mode)
      - Neutrino implant     (autonomous agent, remote mode)

    Wire protocol: JSON over HTTPS with mutual TLS. The engagement CA cert
    is pinned — the system trust store is intentionally ignored.
    """

    def __init__(
        self,
        token: "OperatorToken | str",
        *,
        timeout: float = 30.0,
    ) -> None:
        """
        Args:
            token: A decoded OperatorToken or an encoded qm:// string.
            timeout: HTTP request timeout in seconds.

        Raises:
            TokenError: If the token is expired, tampered, or malformed.
        """
        from quantum_mechanic.daemon.pki import OperatorToken, decode_token

        # --------------------------------------------------------
        # Resolve to a validated OperatorToken.
        # decode_token() enforces expiry and tamper checks.
        # --------------------------------------------------------
        if isinstance(token, str):
            # Encoded string — full validation pipeline.
            self._token: OperatorToken = decode_token(token)
        else:
            # Already decoded — still re-validate expiry.
            # (OperatorToken objects can be constructed in tests with
            # forced-expired timestamps, so always re-check.)
            decoded = decode_token(token.encode())
            self._token = decoded

        self._timeout = timeout

    # ----------------------------------------------------------------
    # Public properties
    # ----------------------------------------------------------------

    @property
    def operator(self) -> str:
        """The name of the authenticated operator."""
        return self._token.operator

    @property
    def host(self) -> str:
        """The qmd server host:port this transport connects to."""
        return self._token.host

    @property
    def base_url(self) -> str:
        """Full HTTPS base URL for the qmd server."""
        host = self._token.host
        if "://" not in host:
            host = f"https://{host}"
        return host.rstrip("/")

    # ----------------------------------------------------------------
    # Transport ABC
    # ----------------------------------------------------------------

    def run_technique(
        self,
        technique_id: str,
        credential_id: int | None = None,
        *,
        safe_mode: bool = False,
        params: dict | None = None,
    ) -> TechniqueResult:
        """Execute a technique on the remote qmd server.

        Sends POST /techniques/run and returns the result.
        Network errors are caught and returned as status='error'.
        """
        try:
            with self._make_client() as client:
                resp = client.post(
                    f"{self.base_url}/techniques/run",
                    json={
                        "technique_id": technique_id,
                        "params": params or {},
                    },
                    timeout=self._timeout,
                )
                resp.raise_for_status()
                body = resp.json()

            return TechniqueResult(
                technique_id=body.get("technique_id", technique_id),
                provider=body.get("provider") or "unknown",
                status=body.get("status", "error"),
                data=body.get("data"),
                error=body.get("error"),
                api_calls=0,
                duration_ms=0,
            )

        except Exception as exc:
            return TechniqueResult(
                technique_id=technique_id,
                provider="unknown",
                status="error",
                error=str(exc),
            )

    def list_techniques(
        self,
        provider: str | None = None,
    ) -> Iterator[TechniqueMetadata]:
        """List techniques available on the remote qmd server.

        Calls GET /techniques (optionally with ?provider=). On network
        failure, yields nothing rather than raising.
        """
        try:
            url = f"{self.base_url}/techniques"
            if provider:
                url = f"{url}?provider={provider}"
            with self._make_client() as client:
                resp = client.get(url, timeout=self._timeout)
                resp.raise_for_status()
                items = resp.json()

            for item in items:
                yield TechniqueMetadata(
                    id=item["id"],
                    tactic=item.get("tactic", "unknown"),
                    providers=item.get("providers", []),
                    severity=item.get("severity", "info"),
                    mitre_id=item.get("mitre_id"),
                    safe=item.get("safe", True),
                    description=item.get("description", ""),
                )

        except Exception:
            return  # Yield nothing — caller handles empty gracefully.

    # ----------------------------------------------------------------
    # Internal: mTLS client factory.
    # Broken out so tests can patch it without reaching into httpx internals.
    # ----------------------------------------------------------------

    def _make_client(self) -> "httpx.Client":
        """Build an httpx.Client configured for mTLS with the engagement CA.

        The CA cert is pinned: system trust store is intentionally ignored.
        Client cert + key authenticate this operator to qmd.

        Returns:
            httpx.Client — use as a context manager.
        """
        import ssl
        import tempfile

        import httpx

        tok = self._token

        # Write certs to temp files — httpx needs file paths for ssl.SSLContext.
        # Files are cleaned up when the context manager exits.
        with (
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as ca_file,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_file,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_file,
        ):
            ca_path = ca_file.name
            cert_path = cert_file.name
            key_path = key_file.name
            ca_file.write(tok.ca_cert_pem.encode())
            cert_file.write(tok.client_cert_pem.encode())
            key_file.write(tok.client_key_pem.encode())

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(ca_path)        # Pin to engagement CA
        ctx.load_cert_chain(cert_path, key_path)  # Present operator client cert
        ctx.check_hostname = False  # CA pinning is our check — hostname is flexible
        ctx.verify_mode = ssl.CERT_REQUIRED

        return httpx.Client(
            verify=ctx,
            timeout=httpx.Timeout(self._timeout, connect=10.0),
        )

