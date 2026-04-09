"""Adapter registry with trust validation.

Adapters must be registered through this registry. The registry validates
that adapter implementations come from trusted sources before accepting
them. Trust is established via:

1. Package namespace verification — adapter class must originate from
   a trusted package (default: `gauth_adapters_gimel.*`)
2. Optional cryptographic signature verification
3. Explicit trust grants for development/testing
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Any, Type

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    ComplianceEnrichmentAdapter,
    RegulatoryReasoningAdapter,
    RiskScoringAdapter,
)
from gauth_core.adapters.defaults import (
    NoOpAIEnrichmentAdapter,
    NoOpComplianceEnrichmentAdapter,
    NoOpRegulatoryReasoningAdapter,
    NoOpRiskScoringAdapter,
)

logger = logging.getLogger(__name__)

ADAPTER_BASE_TYPES = {
    "ai_enrichment": AIEnrichmentAdapter,
    "risk_scoring": RiskScoringAdapter,
    "regulatory_reasoning": RegulatoryReasoningAdapter,
    "compliance_enrichment": ComplianceEnrichmentAdapter,
}

TRUSTED_NAMESPACES = frozenset({
    "gauth_adapters_gimel",
    "gauth_core.adapters.defaults",
})


class AdapterRegistrationError(Exception):
    pass


class AdapterRegistry:

    def __init__(
        self,
        trusted_namespaces: frozenset[str] | None = None,
        signing_key: bytes | None = None,
        allow_untrusted: bool = False,
    ) -> None:
        self._trusted_namespaces = trusted_namespaces or TRUSTED_NAMESPACES
        self._signing_key = signing_key
        self._allow_untrusted = allow_untrusted
        self._adapters: dict[str, Any] = {
            "ai_enrichment": NoOpAIEnrichmentAdapter(),
            "risk_scoring": NoOpRiskScoringAdapter(),
            "regulatory_reasoning": NoOpRegulatoryReasoningAdapter(),
            "compliance_enrichment": NoOpComplianceEnrichmentAdapter(),
        }

    def _is_trusted_namespace(self, adapter: Any) -> bool:
        module = type(adapter).__module__ or ""
        return any(module.startswith(ns) for ns in self._trusted_namespaces)

    def _verify_signature(self, adapter: Any, signature: bytes) -> bool:
        if not self._signing_key:
            return False
        adapter_id = f"{type(adapter).__module__}.{type(adapter).__qualname__}"
        expected = hmac.new(self._signing_key, adapter_id.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    def register(
        self,
        adapter: Any,
        adapter_type: str | None = None,
        signature: bytes | None = None,
        force: bool = False,
    ) -> None:
        if adapter_type is None:
            adapter_type = getattr(adapter, "ADAPTER_TYPE", None)
            if adapter_type is None:
                raise AdapterRegistrationError(
                    "Adapter must have ADAPTER_TYPE attribute or adapter_type must be provided"
                )

        if adapter_type not in ADAPTER_BASE_TYPES:
            raise AdapterRegistrationError(f"Unknown adapter type: {adapter_type}")

        base_type = ADAPTER_BASE_TYPES[adapter_type]
        if not isinstance(adapter, base_type):
            raise AdapterRegistrationError(
                f"Adapter must be an instance of {base_type.__name__}"
            )

        trusted = self._is_trusted_namespace(adapter)

        if not trusted and signature is not None:
            trusted = self._verify_signature(adapter, signature)

        if not trusted and not self._allow_untrusted and not force:
            raise AdapterRegistrationError(
                f"Adapter from module '{type(adapter).__module__}' is not from a trusted namespace. "
                f"Trusted namespaces: {sorted(self._trusted_namespaces)}. "
                "Use allow_untrusted=True in the registry constructor for development, "
                "or provide a valid signature."
            )

        if not trusted:
            logger.warning(
                "Registering untrusted adapter %s.%s for slot '%s'",
                type(adapter).__module__,
                type(adapter).__qualname__,
                adapter_type,
            )

        self._adapters[adapter_type] = adapter
        logger.info("Registered adapter for '%s': %s", adapter_type, type(adapter).__qualname__)

    @property
    def ai_enrichment(self) -> AIEnrichmentAdapter:
        return self._adapters["ai_enrichment"]

    @property
    def risk_scoring(self) -> RiskScoringAdapter:
        return self._adapters["risk_scoring"]

    @property
    def regulatory_reasoning(self) -> RegulatoryReasoningAdapter:
        return self._adapters["regulatory_reasoning"]

    @property
    def compliance_enrichment(self) -> ComplianceEnrichmentAdapter:
        return self._adapters["compliance_enrichment"]

    def get(self, adapter_type: str) -> Any:
        if adapter_type not in self._adapters:
            raise KeyError(f"No adapter registered for type: {adapter_type}")
        return self._adapters[adapter_type]

    def list_registered(self) -> dict[str, str]:
        return {
            k: type(v).__qualname__
            for k, v in self._adapters.items()
        }
