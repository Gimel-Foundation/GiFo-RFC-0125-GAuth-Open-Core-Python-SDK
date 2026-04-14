"""Conformance tests for Gap Spec Block A — G-01, G-02, G-08.

Test IDs follow the Gap Specification v1.2.0 §4.2 naming:
  CT-TM-*    Tariff Model
  CT-REG-*   Adapter Registration enforcement
  CT-LIC-*   License & Attestation
"""

import os
import time

import pytest

from gauth_core.adapters.base import AIEnrichmentAdapter
from gauth_core.adapters.defaults import (
    NoOpAIEnrichmentAdapter,
    NoOpComplianceEnrichmentAdapter,
    NoOpRegulatoryReasoningAdapter,
    NoOpRiskScoringAdapter,
)
from gauth_core.adapters.registry import AdapterRegistry, AdapterRegistrationError
from gauth_core.pep.engine import PEPEngine
from gauth_core.schema.enums import (
    DEPLOYMENT_POLICY_MATRIX,
    Tariff,
    check_tariff_gate,
    tariff_effective_level,
)


class _FakeAIAdapter(AIEnrichmentAdapter):
    ADAPTER_TYPE = "ai_enrichment"

    def enrich(self, enforcement_request, mandate):
        return {"enrichment_source": "fake_ai", "signals": ["threat_detected"]}

    def health_check(self):
        return True


class TestTariffModelConformance:
    """CT-TM-001/002/003 — Tariff enum, effective level, S column."""

    def test_ct_tm_001_tariff_enum_contains_all_values(self):
        assert Tariff.O.value == "O"
        assert Tariff.S.value == "S"
        assert Tariff.M.value == "M"
        assert Tariff.L.value == "L"
        assert Tariff.MO.value == "M+O"
        assert Tariff.LO.value == "L+O"
        assert len(Tariff) == 6

    def test_ct_tm_002_tariff_effective_level_s(self):
        assert tariff_effective_level(Tariff.S) == "S"
        assert tariff_effective_level(Tariff.O) == "O"
        assert tariff_effective_level(Tariff.M) == "M"
        assert tariff_effective_level(Tariff.L) == "L"
        assert tariff_effective_level(Tariff.MO) == "M"
        assert tariff_effective_level(Tariff.LO) == "L"

    def test_ct_tm_003_deployment_policy_matrix_has_s_column(self):
        for slot_name, matrix in DEPLOYMENT_POLICY_MATRIX.items():
            assert "S" in matrix, f"Slot '{slot_name}' missing S column"
        assert DEPLOYMENT_POLICY_MATRIX["pdp"]["S"] == "active_always"
        assert DEPLOYMENT_POLICY_MATRIX["oauth_engine"]["S"] == "gimel_or_user"
        assert DEPLOYMENT_POLICY_MATRIX["foundry"]["S"] == "gimel_or_user"
        assert DEPLOYMENT_POLICY_MATRIX["wallet"]["S"] == "gimel_or_user"
        assert DEPLOYMENT_POLICY_MATRIX["ai_governance"]["S"] == "null"
        assert DEPLOYMENT_POLICY_MATRIX["web3_identity"]["S"] == "null"
        assert DEPLOYMENT_POLICY_MATRIX["dna_identity"]["S"] == "null"


class TestRegistrationEnforcementConformance:
    """CT-REG-019 to CT-REG-023, CT-REG-028/029/030."""

    def test_ct_reg_019_register_rejects_type_c_on_tariff_o(self):
        registry = AdapterRegistry(tariff=Tariff.O)
        adapter = _FakeAIAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter)
        assert exc_info.value.error_code == "TARIFF_GATE_DENIED"

    def test_ct_reg_020_force_without_license_raises_license_required(self):
        registry = AdapterRegistry(tariff=Tariff.O)
        adapter = NoOpAIEnrichmentAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter, force=True)
        assert exc_info.value.error_code == "LICENSE_REQUIRED"

    def test_ct_reg_020_force_with_license_succeeds(self):
        registry = AdapterRegistry(tariff=Tariff.O, license_token="gimel_valid_token_1234567890")
        adapter = NoOpAIEnrichmentAdapter()
        registry.register(adapter, force=True)
        assert registry.ai_enrichment is adapter

    def test_ct_reg_021_allow_untrusted_without_dev_mode_ignored(self):
        old_val = os.environ.get("GAUTH_DEV_MODE")
        os.environ.pop("GAUTH_DEV_MODE", None)
        try:
            registry = AdapterRegistry(allow_untrusted=True, tariff=Tariff.O)
            assert registry._allow_untrusted is False
        finally:
            if old_val is not None:
                os.environ["GAUTH_DEV_MODE"] = old_val

    def test_ct_reg_021_allow_untrusted_with_dev_mode_works(self):
        old_val = os.environ.get("GAUTH_DEV_MODE")
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            registry = AdapterRegistry(allow_untrusted=True, tariff=Tariff.O)
            assert registry._allow_untrusted is True
        finally:
            if old_val is not None:
                os.environ["GAUTH_DEV_MODE"] = old_val
            else:
                os.environ.pop("GAUTH_DEV_MODE", None)

    def test_ct_reg_022_type_c_requires_manifest(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter)
        assert exc_info.value.error_code == "ATTESTATION_REQUIRED"

    def test_ct_reg_022_type_c_invalid_manifest_rejected(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter, manifest={})
        assert exc_info.value.error_code == "ATTESTATION_REQUIRED"

    def test_ct_reg_022_type_c_manifest_wrong_namespace(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        manifest = {
            "manifest_version": "1.0",
            "adapter_type": "ai_enrichment",
            "slot_name": "ai_governance",
            "namespace": "@community/ai-adapter",
            "issued_at": time.time() - 60,
            "expires_at": time.time() + 3600,
            "public_key": "deadbeef",
            "signature": "deadbeef",
            "checksum": "abc123",
        }
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter, manifest=manifest)
        assert "namespace" in str(exc_info.value).lower()

    def test_ct_reg_022_type_c_manifest_expired(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        manifest = {
            "manifest_version": "1.0",
            "adapter_type": "ai_enrichment",
            "slot_name": "ai_governance",
            "namespace": "@gimel/ai-governance",
            "issued_at": time.time() - 7200,
            "expires_at": time.time() - 3600,
            "public_key": "deadbeef",
            "signature": "deadbeef",
            "checksum": "abc123",
        }
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter, manifest=manifest)
        assert "expired" in str(exc_info.value).lower()

    def test_ct_reg_022_type_c_manifest_revoked_key(self):
        registry = AdapterRegistry(
            tariff=Tariff.M, revoked_keys={"deadbeef"}
        )
        adapter = _FakeAIAdapter()
        manifest = {
            "manifest_version": "1.0",
            "adapter_type": "ai_enrichment",
            "slot_name": "ai_governance",
            "namespace": "@gimel/ai-governance",
            "issued_at": time.time() - 60,
            "expires_at": time.time() + 3600,
            "public_key": "deadbeef",
            "signature": "deadbeef",
            "checksum": "abc123",
        }
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter, manifest=manifest)
        assert "revoked" in str(exc_info.value).lower()

    def test_ct_reg_023_tariff_downgrade_deactivates_adapters(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        assert type(registry.ai_enrichment).__qualname__ == "_FakeAIAdapter"
        deactivated = registry.change_tariff(Tariff.O)
        assert len(deactivated) >= 1
        assert any(d["adapter_type"] == "ai_enrichment" for d in deactivated)
        assert type(registry.ai_enrichment).__qualname__ == "NoOpAIEnrichmentAdapter"

    def test_ct_reg_023_tariff_downgrade_audit_log(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        registry.change_tariff(Tariff.O)
        audit = registry.audit_log
        deactivation_events = [
            e for e in audit if e["event"] == "adapter_deactivated_tariff_downgrade"
        ]
        assert len(deactivation_events) >= 1

    def test_ct_reg_028_s_tier_ai_governance_blocked(self):
        result = check_tariff_gate("ai_governance", Tariff.S)
        assert result.allowed is False

    def test_ct_reg_029_s_tier_oauth_engine_allowed(self):
        result = check_tariff_gate("oauth_engine", Tariff.S)
        assert result.allowed is True

    def test_ct_reg_030_register_type_c_on_tariff_s_rejected(self):
        registry = AdapterRegistry(tariff=Tariff.S)
        adapter = _FakeAIAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter)
        assert exc_info.value.error_code == "TARIFF_GATE_DENIED"

    def test_noop_adapter_on_blocked_slot_allowed(self):
        registry = AdapterRegistry(tariff=Tariff.O)
        adapter = NoOpAIEnrichmentAdapter()
        registry.register(adapter)
        assert type(registry.ai_enrichment).__qualname__ == "NoOpAIEnrichmentAdapter"

    def test_tariff_gate_reason_included_in_error(self):
        registry = AdapterRegistry(tariff=Tariff.O)
        adapter = _FakeAIAdapter()
        with pytest.raises(AdapterRegistrationError) as exc_info:
            registry.register(adapter)
        assert "not available" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower()

    def test_slot_name_override_removed_from_register(self):
        import inspect
        sig = inspect.signature(AdapterRegistry.register)
        assert "slot_name" not in sig.parameters

    def test_license_token_too_short_rejected(self):
        registry = AdapterRegistry(tariff=Tariff.O, license_token="short")
        assert registry._license_token is None

    def test_license_token_empty_rejected(self):
        registry = AdapterRegistry(tariff=Tariff.O, license_token="")
        assert registry._license_token is None

    def test_license_token_whitespace_only_rejected(self):
        registry = AdapterRegistry(tariff=Tariff.O, license_token="               ")
        assert registry._license_token is None

    def test_license_token_valid_accepted(self):
        registry = AdapterRegistry(tariff=Tariff.O, license_token="gimel_valid_token_1234567890")
        assert registry._license_token == "gimel_valid_token_1234567890"


class TestLicenseComplianceConformance:
    """CT-LIC-010/011 — PEP init detection + compliance violation logging."""

    def test_ct_lic_010_pep_init_detects_tariff_adapter_mismatch(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        registry._tariff = Tariff.O
        engine = PEPEngine(adapter_registry=registry)
        assert len(engine.compliance_violations) >= 1
        violation = engine.compliance_violations[0]
        assert violation["error_code"] == "LICENSE_COMPLIANCE_VIOLATION"

    def test_ct_lic_011_non_noop_on_tariff_o_compliance_violation(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        registry._tariff = Tariff.O
        violations = registry.validate_tariff_compliance()
        assert len(violations) >= 1
        assert any(
            v["error_code"] == "LICENSE_COMPLIANCE_VIOLATION"
            for v in violations
        )

    def test_pep_engine_skips_non_compliant_enrichment(self):
        from datetime import datetime, timedelta, timezone
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        registry._tariff = Tariff.O
        engine = PEPEngine(adapter_registry=registry)
        credential = {
            "mandate_id": "mdt_test",
            "subject": "agent_1",
            "governance_profile": "minimal",
            "phase": "build",
            "core_verbs": {"file.read": {"allowed": True}},
            "platform_permissions": {},
            "allowed_paths": ["src/"],
            "denied_paths": [],
            "allowed_sectors": [],
            "allowed_regions": [],
            "approval_mode": "autonomous",
            "budget_total_cents": 10000,
            "budget_remaining_cents": 5000,
            "ttl_seconds": 43200,
            "scope_checksum": "sha256:abc",
            "tool_permissions_hash": "sha256:def",
            "platform_permissions_hash": "sha256:ghi",
            "exp": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
            "nbf": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "status": "ACTIVE",
            "delegation_chain": [],
            "session_limits": {"max_tool_calls": 500, "max_session_duration_minutes": 240},
        }
        result = engine.enforce_action(
            credential=credential,
            action={"verb": "file.read", "resource": "src/main.py"},
            context={"agent_id": "agent_1"},
        )
        assert "enrichment" not in result.get("audit", {})

    def test_no_violations_when_all_adapters_noop(self):
        registry = AdapterRegistry(tariff=Tariff.O)
        engine = PEPEngine(adapter_registry=registry)
        assert len(engine.compliance_violations) == 0

    def test_no_violations_when_tariff_permits(self):
        registry = AdapterRegistry(tariff=Tariff.M)
        adapter = _FakeAIAdapter()
        registry._adapters["ai_enrichment"] = adapter
        engine = PEPEngine(adapter_registry=registry)
        assert len(engine.compliance_violations) == 0
