"""Tests for Pydantic schema validation."""

import pytest
from pydantic import ValidationError

from gauth_core.schema.poa import (
    Budget,
    MandateRequirements,
    MandateScope,
    PlatformPermissions,
    SessionLimits,
    ToolPolicy,
)
from gauth_core.schema.mgmt import MandateCreationRequest, MandateParties
from gauth_core.schema.enums import GovernanceProfile, MandateStatus, ApprovalMode


class TestToolPolicy:
    def test_default(self):
        p = ToolPolicy()
        assert p.allowed is True
        assert p.requires_approval is False

    def test_custom(self):
        p = ToolPolicy(allowed=False, requires_approval=True, max_per_session=10)
        assert p.allowed is False
        assert p.max_per_session == 10


class TestBudget:
    def test_valid(self):
        b = Budget(total_cents=1000)
        assert b.total_cents == 1000

    def test_zero_valid(self):
        b = Budget(total_cents=0)
        assert b.total_cents == 0

    def test_negative_invalid(self):
        with pytest.raises(ValidationError):
            Budget(total_cents=-1)


class TestMandateCreationRequest:
    def test_valid_minimal(self):
        req = MandateCreationRequest(
            parties=MandateParties(
                subject="agent_1",
                customer_id="cust_1",
                project_id="proj_1",
                issued_by="user_1",
            ),
            scope=MandateScope(
                governance_profile="minimal",
                phase="build",
            ),
            requirements=MandateRequirements(
                approval_mode="autonomous",
                budget=Budget(total_cents=5000),
                ttl_seconds=3600,
            ),
        )
        assert req.parties.subject == "agent_1"
        assert req.scope.governance_profile == "minimal"

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            MandateCreationRequest(
                parties=MandateParties(subject="a", customer_id="c", project_id="p", issued_by="u"),
                scope=MandateScope(governance_profile="minimal", phase="build"),
                requirements={},
            )

    def test_ttl_too_short(self):
        with pytest.raises(ValidationError):
            MandateRequirements(
                approval_mode="autonomous",
                budget=Budget(total_cents=100),
                ttl_seconds=30,
            )


class TestPoACredential:
    def test_valid_credential(self):
        from gauth_core.schema.poa import PoACredential
        cred = PoACredential(
            mandate_id="mdt_abc",
            subject="agent_1",
            governance_profile="minimal",
            phase="build",
        )
        assert cred.mandate_id == "mdt_abc"
        assert cred.governance_profile == "minimal"

    def test_invalid_profile_rejected(self):
        from gauth_core.schema.poa import PoACredential
        with pytest.raises(ValidationError):
            PoACredential(
                mandate_id="mdt_abc",
                subject="agent_1",
                governance_profile="invalid_profile",
                phase="build",
            )

    def test_invalid_approval_mode_rejected(self):
        from gauth_core.schema.poa import PoACredential
        with pytest.raises(ValidationError):
            PoACredential(
                mandate_id="mdt_abc",
                subject="agent_1",
                governance_profile="minimal",
                phase="build",
                approval_mode="invalid_mode",
            )


class TestMandateScopeEnumValidation:
    def test_invalid_governance_profile_rejected(self):
        from gauth_core.schema.poa import MandateScope
        with pytest.raises(ValidationError):
            MandateScope(governance_profile="bogus", phase="build")

    def test_valid_governance_profile_accepted(self):
        from gauth_core.schema.poa import MandateScope
        s = MandateScope(governance_profile="enterprise", phase="build")
        assert s.governance_profile == "enterprise"


class TestEnums:
    def test_governance_profiles(self):
        assert len(GovernanceProfile) == 5
        assert GovernanceProfile.BEHOERDE.value == "behoerde"

    def test_mandate_statuses(self):
        assert len(MandateStatus) == 9
        assert MandateStatus.BUDGET_EXCEEDED.value == "BUDGET_EXCEEDED"


class TestTariffEnum:
    def test_tariff_values(self):
        from gauth_core.schema.enums import Tariff
        assert Tariff.O.value == "O"
        assert Tariff.S.value == "S"
        assert Tariff.M.value == "M"
        assert Tariff.L.value == "L"
        assert Tariff.MO.value == "M+O"
        assert Tariff.LO.value == "L+O"
        assert len(Tariff) == 6

    def test_tariff_effective_level(self):
        from gauth_core.schema.enums import Tariff, tariff_effective_level
        assert tariff_effective_level(Tariff.O) == "O"
        assert tariff_effective_level(Tariff.S) == "S"
        assert tariff_effective_level(Tariff.M) == "M"
        assert tariff_effective_level(Tariff.L) == "L"
        assert tariff_effective_level(Tariff.MO) == "M"
        assert tariff_effective_level(Tariff.LO) == "L"

    def test_open_core_active(self):
        from gauth_core.schema.enums import Tariff, is_open_core_active
        assert is_open_core_active(Tariff.O) is False
        assert is_open_core_active(Tariff.S) is False
        assert is_open_core_active(Tariff.M) is False
        assert is_open_core_active(Tariff.L) is False
        assert is_open_core_active(Tariff.MO) is True
        assert is_open_core_active(Tariff.LO) is True

    def test_mo_treated_as_m_for_adapter_access(self):
        from gauth_core.schema.enums import Tariff, TARIFF_ADAPTER_ACCESS
        assert TARIFF_ADAPTER_ACCESS[Tariff.MO] == "M"

    def test_lo_treated_as_l_for_adapter_access(self):
        from gauth_core.schema.enums import Tariff, TARIFF_ADAPTER_ACCESS
        assert TARIFF_ADAPTER_ACCESS[Tariff.LO] == "L"

    def test_standalone_tariff_access(self):
        from gauth_core.schema.enums import Tariff, TARIFF_ADAPTER_ACCESS
        assert TARIFF_ADAPTER_ACCESS[Tariff.S] == "S"
        assert TARIFF_ADAPTER_ACCESS[Tariff.M] == "M"
        assert TARIFF_ADAPTER_ACCESS[Tariff.L] == "L"


class TestPoaMapSummary:
    def test_poa_map_summary_defaults(self):
        from gauth_core.schema.mgmt import PoaMapSummary
        summary = PoaMapSummary(
            mandate_id="mdt_123",
            subject="agent_1",
            governance_profile="minimal",
            status=MandateStatus.ACTIVE,
        )
        assert summary.permissions == []
        assert summary.allowed_actions == []
        assert summary.allowed_decisions == []

    def test_poa_map_summary_with_permissions(self):
        from gauth_core.schema.mgmt import PoaMapSummary, PoaPermissionEntry
        entry = PoaPermissionEntry(action="file.read", resource="src/", effect="allow")
        summary = PoaMapSummary(
            mandate_id="mdt_123",
            subject="agent_1",
            governance_profile="standard",
            status=MandateStatus.ACTIVE,
            permissions=[entry],
            allowed_actions=["file.read", "file.write"],
            allowed_decisions=["approve", "reject"],
        )
        assert len(summary.permissions) == 1
        assert summary.permissions[0].action == "file.read"
        assert summary.permissions[0].resource == "src/"
        assert summary.permissions[0].effect == "allow"
        assert summary.allowed_actions == ["file.read", "file.write"]
        assert summary.allowed_decisions == ["approve", "reject"]

    def test_poa_permission_entry_optional_resource(self):
        from gauth_core.schema.mgmt import PoaPermissionEntry
        entry = PoaPermissionEntry(action="deploy", effect="deny")
        assert entry.resource is None
        assert entry.action == "deploy"
        assert entry.effect == "deny"

    def test_poa_map_summary_camel_case_aliases(self):
        from gauth_core.schema.mgmt import PoaMapSummary
        summary = PoaMapSummary(
            mandate_id="mdt_123",
            subject="agent_1",
            governance_profile="minimal",
            status=MandateStatus.ACTIVE,
            allowed_actions=["file.read"],
            allowed_decisions=["approve"],
        )
        assert summary.allowed_actions == ["file.read"]
        assert summary.allowed_decisions == ["approve"]

    def test_poa_map_summary_accepts_camel_case_input(self):
        from gauth_core.schema.mgmt import PoaMapSummary
        summary = PoaMapSummary(
            mandate_id="mdt_123",
            subject="agent_1",
            governance_profile="minimal",
            status=MandateStatus.ACTIVE,
            allowedActions=["file.read"],
            allowedDecisions=["approve"],
        )
        assert summary.allowed_actions == ["file.read"]
        assert summary.allowed_decisions == ["approve"]

    def test_poa_map_summary_serialization_includes_alias(self):
        from gauth_core.schema.mgmt import PoaMapSummary
        summary = PoaMapSummary(
            mandate_id="mdt_123",
            subject="agent_1",
            governance_profile="minimal",
            status=MandateStatus.ACTIVE,
            allowed_actions=["file.read"],
            allowed_decisions=["approve"],
        )
        data = summary.model_dump(by_alias=True)
        assert "allowedActions" in data
        assert "allowedDecisions" in data
        assert data["allowedActions"] == ["file.read"]


class TestTariffGating:
    def test_mo_ai_governance_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.MO)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_lo_ai_governance_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.LO)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_o_ai_governance_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.O)
        assert result.allowed is False
        assert result.availability == "null"

    def test_o_pdp_always_active(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("pdp", Tariff.O)
        assert result.allowed is True
        assert result.availability == "active_always"

    def test_mo_pdp_always_active(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("pdp", Tariff.MO)
        assert result.allowed is True
        assert result.availability == "active_always"

    def test_mo_dna_identity_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("dna_identity", Tariff.MO)
        assert result.allowed is False
        assert result.availability == "null"

    def test_lo_dna_identity_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("dna_identity", Tariff.LO)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_o_oauth_engine_user_provided(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("oauth_engine", Tariff.O)
        assert result.allowed is True
        assert result.availability == "user_provided_required"

    def test_mo_oauth_engine_gimel_or_user(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("oauth_engine", Tariff.MO)
        assert result.allowed is True
        assert result.availability == "gimel_or_user"

    def test_mo_web3_identity_attested(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("web3_identity", Tariff.MO)
        assert result.allowed is True
        assert result.availability == "null_or_attested_gimel"

    def test_lo_web3_identity_attested(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("web3_identity", Tariff.LO)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_o_web3_identity_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("web3_identity", Tariff.O)
        assert result.allowed is False
        assert result.availability == "null"

    def test_unknown_slot_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("nonexistent", Tariff.MO)
        assert result.allowed is False

    def test_s_ai_governance_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.S)
        assert result.allowed is False
        assert result.availability == "null"

    def test_s_oauth_engine_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("oauth_engine", Tariff.S)
        assert result.allowed is True
        assert result.availability == "gimel_or_user"

    def test_s_pdp_always_active(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("pdp", Tariff.S)
        assert result.allowed is True
        assert result.availability == "active_always"

    def test_s_web3_identity_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("web3_identity", Tariff.S)
        assert result.allowed is False

    def test_s_dna_identity_blocked(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("dna_identity", Tariff.S)
        assert result.allowed is False

    def test_s_wallet_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("wallet", Tariff.S)
        assert result.allowed is True
        assert result.availability == "gimel_or_user"

    def test_m_standalone_ai_governance_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.M)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_l_standalone_dna_identity_allowed(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("dna_identity", Tariff.L)
        assert result.allowed is True
        assert result.availability == "attested_gimel"

    def test_gate_reason_included(self):
        from gauth_core.schema.enums import Tariff, check_tariff_gate
        result = check_tariff_gate("ai_governance", Tariff.O)
        assert result.reason != ""
        assert "not available" in result.reason
