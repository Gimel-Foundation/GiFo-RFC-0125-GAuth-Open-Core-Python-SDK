"""Abstract adapter interfaces for proprietary Gimel service extensions.

These interfaces define the extension points where proprietary services
(AI enrichment, risk scoring, regulatory reasoning, compliance) can be
plugged into the GAuth Open Core. The core 16-check PEP pipeline is
never altered by adapters — they operate at defined hook points
(pre-evaluation enrichment, post-evaluation compliance).

Adapters are registered through the AdapterRegistry with trust validation.
Only signed or namespace-verified adapter implementations are accepted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIEnrichmentAdapter(ABC):
    """Pre-evaluation AI enrichment — proprietary extension point.

    Called before the PEP evaluation pipeline to enrich the enforcement
    request with AI-derived context (threat analysis, intent classification,
    risk signals). The enrichment output is advisory — it does not alter
    the deterministic PEP checks but may add metadata to the audit record.
    """

    ADAPTER_TYPE = "ai_enrichment"

    @abstractmethod
    def enrich(
        self,
        enforcement_request: dict[str, Any],
        mandate: dict[str, Any],
    ) -> dict[str, Any]:
        """Return enrichment metadata to attach to the enforcement context."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class RiskScoringAdapter(ABC):
    """Risk scoring — proprietary extension point.

    Computes a composite risk score for a mandate creation or enforcement
    request. Used by AI-assisted registration paths (Paths 1-3) to guide
    governance profile selection and constraint recommendations.
    """

    ADAPTER_TYPE = "risk_scoring"

    @abstractmethod
    def score(
        self,
        mandate_data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return risk assessment with score, factors, and recommendations."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class RegulatoryReasoningAdapter(ABC):
    """Regulatory reasoning — proprietary extension point.

    Provides regulatory interpretation and compliance analysis for mandate
    creation. Maps governance profiles to regulatory requirements based on
    sector, region, and organizational context.
    """

    ADAPTER_TYPE = "regulatory_reasoning"

    @abstractmethod
    def analyze(
        self,
        mandate_data: dict[str, Any],
        regulatory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return regulatory analysis with requirements and recommendations."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class ComplianceEnrichmentAdapter(ABC):
    """Post-evaluation compliance enrichment — proprietary extension point.

    Called after the PEP evaluation pipeline to add compliance-layer
    analysis (architecture compliance, prompt injection detection,
    outbound content scanning). Results are non-normative and clearly
    separated from PEP decisions in the output.
    """

    ADAPTER_TYPE = "compliance_enrichment"

    @abstractmethod
    def evaluate(
        self,
        enforcement_decision: dict[str, Any],
        enforcement_request: dict[str, Any],
    ) -> dict[str, Any]:
        """Return compliance enrichment results (non-normative)."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...
