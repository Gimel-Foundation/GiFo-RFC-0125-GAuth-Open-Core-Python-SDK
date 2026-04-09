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
        assert len(MandateStatus) == 7
        assert MandateStatus.BUDGET_EXCEEDED.value == "BUDGET_EXCEEDED"
