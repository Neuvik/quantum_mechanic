# ================================================================
# MODULE: quantum_mechanic.providers.base
# ----------------------------------------------------------------
# PURPOSE:   Abstract interfaces for cloud providers. Every
#            provider (AWS, Azure, GCP, OCI) implements these
#            interfaces so techniques can be provider-agnostic.
#
# DESIGN:    MVP exposes only AuthProvider (authenticate + whoami).
#            IdentityProvider, ComputeProvider, and StorageProvider
#            will be added as techniques require them.
# ================================================================

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class WhoAmIResult:
    """Result of a whoami operation across any provider.

    Normalizes the identity information so techniques and the
    shell can display it uniformly regardless of cloud provider.
    """

    provider: str
    principal_id: str  # Provider-native ID (ARN, object ID, email, OCID)
    principal_type: str  # user, role, service_account, etc.
    friendly_name: str  # Human-readable ("svc-deploy", "j.smith@acme")
    account_id: str  # Account/subscription/project/tenancy ID
    account_name: str | None = None  # Human-readable account name
    tenant_id: str | None = None  # Azure tenant, GCP org, OCI tenancy
    extra: dict[str, Any] | None = None  # Provider-specific additional info
    raw_response: dict[str, Any] | None = None  # Full API response


class AuthProvider(ABC):
    """Abstract authentication provider.

    Each cloud provider implements this to handle credential
    loading and identity resolution.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider identifier (aws, azure, gcp, oci)."""
        ...

    @abstractmethod
    def authenticate(self, secret_data: dict[str, Any]) -> Any:
        """Create an authenticated session from credential data.

        Args:
            secret_data: Decrypted credential material. Format
                varies by provider and credential type.

        Returns:
            Provider-specific session object.
        """
        ...

    @abstractmethod
    def whoami(self, session: Any) -> WhoAmIResult:
        """Identify the principal for the current session.

        Args:
            session: Authenticated session from authenticate().

        Returns:
            Normalized identity information.
        """
        ...


class ProviderRegistry:
    """Registry of available cloud providers.

    Techniques use this to get the right provider implementation
    without importing provider-specific code directly.
    """

    def __init__(self) -> None:
        self._providers: dict[str, AuthProvider] = {}

    def register(self, provider: AuthProvider) -> None:
        """Register a provider implementation."""
        self._providers[provider.provider_name] = provider

    def get(self, name: str) -> AuthProvider | None:
        """Get a provider by name."""
        return self._providers.get(name)

    def available(self) -> list[str]:
        """List available provider names."""
        return list(self._providers.keys())

    def get_or_raise(self, name: str) -> AuthProvider:
        """Get a provider by name, raising if not found."""
        provider = self._providers.get(name)
        if provider is None:
            available = ", ".join(self._providers.keys()) or "none"
            raise ValueError(f"Provider '{name}' not available. Available: {available}")
        return provider
