"""Tests for the adapter system — registration and trust validation."""

import os
import pytest

from gauth_core.adapters.base import AIEnrichmentAdapter, ComplianceEnrichmentAdapter
from gauth_core.adapters.defaults import (
    NoOpAIEnrichmentAdapter,
    NoOpComplianceEnrichmentAdapter,
    NoOpRegulatoryReasoningAdapter,
    NoOpRiskScoringAdapter,
)
from gauth_core.adapters.registry import AdapterRegistry, AdapterRegistrationError
from gauth_core.schema.enums import Tariff


class TestDefaultAdapters:
    def test_noop_ai_enrichment(self):
        adapter = NoOpAIEnrichmentAdapter()
        result = adapter.enrich({}, {})
        assert result["enrichment_source"] == "noop"
        assert adapter.health_check() is True

    def test_noop_risk_scoring(self):
        adapter = NoOpRiskScoringAdapter()
        result = adapter.score({})
        assert result["source"] == "noop"

    def test_noop_regulatory_reasoning(self):
        adapter = NoOpRegulatoryReasoningAdapter()
        result = adapter.analyze({})
        assert result["source"] == "noop"

    def test_noop_compliance_enrichment(self):
        adapter = NoOpComplianceEnrichmentAdapter()
        result = adapter.evaluate({}, {})
        assert result["source"] == "noop"


class TestAdapterRegistry:
    def test_defaults_populated(self):
        registry = AdapterRegistry()
        registered = registry.list_registered()
        assert "ai_enrichment" in registered
        assert "risk_scoring" in registered
        assert "regulatory_reasoning" in registered
        assert "compliance_enrichment" in registered

    def test_register_trusted_default(self):
        registry = AdapterRegistry()
        adapter = NoOpAIEnrichmentAdapter()
        registry.register(adapter)
        assert isinstance(registry.ai_enrichment, NoOpAIEnrichmentAdapter)

    def test_register_untrusted_blocked(self):
        registry = AdapterRegistry(allow_untrusted=False, tariff=Tariff.M)

        class UntrustedAdapter(AIEnrichmentAdapter):
            ADAPTER_TYPE = "ai_enrichment"
            def enrich(self, req, mandate):
                return {}
            def health_check(self):
                return True

        with pytest.raises(AdapterRegistrationError):
            registry.register(UntrustedAdapter())

    def test_register_untrusted_allowed(self):
        old_val = os.environ.get("GAUTH_DEV_MODE")
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            registry = AdapterRegistry(allow_untrusted=True, tariff=Tariff.O)

            class TestComplianceAdapter(ComplianceEnrichmentAdapter):
                ADAPTER_TYPE = "compliance_enrichment"
                def evaluate(self, decision, request):
                    return {"source": "test"}
                def health_check(self):
                    return True

            registry.register(TestComplianceAdapter())
            result = registry.compliance_enrichment.evaluate({}, {})
            assert result["source"] == "test"
        finally:
            if old_val is not None:
                os.environ["GAUTH_DEV_MODE"] = old_val
            else:
                os.environ.pop("GAUTH_DEV_MODE", None)

    def test_register_wrong_type(self):
        old_val = os.environ.get("GAUTH_DEV_MODE")
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            registry = AdapterRegistry(allow_untrusted=True, tariff=Tariff.M)

            class WrongType(AIEnrichmentAdapter):
                ADAPTER_TYPE = "ai_enrichment"
                def enrich(self, req, mandate):
                    return {}
                def health_check(self):
                    return True

            with pytest.raises(AdapterRegistrationError):
                registry.register(WrongType(), adapter_type="risk_scoring")
        finally:
            if old_val is not None:
                os.environ["GAUTH_DEV_MODE"] = old_val
            else:
                os.environ.pop("GAUTH_DEV_MODE", None)

    def test_register_unknown_type(self):
        old_val = os.environ.get("GAUTH_DEV_MODE")
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            registry = AdapterRegistry(allow_untrusted=True, tariff=Tariff.M)
            with pytest.raises(AdapterRegistrationError):
                registry.register(NoOpAIEnrichmentAdapter(), adapter_type="nonexistent")
        finally:
            if old_val is not None:
                os.environ["GAUTH_DEV_MODE"] = old_val
            else:
                os.environ.pop("GAUTH_DEV_MODE", None)

    def test_get_adapter(self):
        registry = AdapterRegistry()
        assert registry.get("ai_enrichment") is not None
        with pytest.raises(KeyError):
            registry.get("nonexistent")
