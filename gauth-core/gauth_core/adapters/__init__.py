"""GAuth adapter system — protected extension points for proprietary services."""

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    RiskScoringAdapter,
    RegulatoryReasoningAdapter,
    ComplianceEnrichmentAdapter,
)
from gauth_core.adapters.registry import AdapterRegistry
from gauth_core.adapters.defaults import (
    NoOpAIEnrichmentAdapter,
    NoOpRiskScoringAdapter,
    NoOpRegulatoryReasoningAdapter,
    NoOpComplianceEnrichmentAdapter,
)

__all__ = [
    "AIEnrichmentAdapter",
    "RiskScoringAdapter",
    "RegulatoryReasoningAdapter",
    "ComplianceEnrichmentAdapter",
    "AdapterRegistry",
    "NoOpAIEnrichmentAdapter",
    "NoOpRiskScoringAdapter",
    "NoOpRegulatoryReasoningAdapter",
    "NoOpComplianceEnrichmentAdapter",
]
