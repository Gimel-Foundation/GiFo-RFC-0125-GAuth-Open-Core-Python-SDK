"""No-op/pass-through default adapter implementations.

These are the default adapters shipped with the open-source SDK.
They perform no AI enrichment, risk scoring, regulatory reasoning,
or compliance analysis — they simply pass through with empty results.
"""

from __future__ import annotations

from typing import Any

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    ComplianceEnrichmentAdapter,
    RegulatoryReasoningAdapter,
    RiskScoringAdapter,
)


class NoOpAIEnrichmentAdapter(AIEnrichmentAdapter):

    ADAPTER_TYPE = "ai_enrichment"

    def enrich(
        self,
        enforcement_request: dict[str, Any],
        mandate: dict[str, Any],
    ) -> dict[str, Any]:
        return {"enrichment_source": "noop", "signals": []}

    def health_check(self) -> bool:
        return True


class NoOpRiskScoringAdapter(RiskScoringAdapter):

    ADAPTER_TYPE = "risk_scoring"

    def score(
        self,
        mandate_data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"score": 0.0, "factors": [], "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpRegulatoryReasoningAdapter(RegulatoryReasoningAdapter):

    ADAPTER_TYPE = "regulatory_reasoning"

    def analyze(
        self,
        mandate_data: dict[str, Any],
        regulatory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"requirements": [], "recommendations": [], "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpComplianceEnrichmentAdapter(ComplianceEnrichmentAdapter):

    ADAPTER_TYPE = "compliance_enrichment"

    def evaluate(
        self,
        enforcement_decision: dict[str, Any],
        enforcement_request: dict[str, Any],
    ) -> dict[str, Any]:
        return {"compliance_results": [], "source": "noop"}

    def health_check(self) -> bool:
        return True
