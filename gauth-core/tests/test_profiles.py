"""Tests for governance profile ceiling table and validation."""

import pytest

from gauth_core.profiles.ceilings import (
    CEILING_TABLE,
    get_ceiling,
    list_profiles,
    validate_against_ceiling,
)
from gauth_core.schema.enums import ApprovalMode, GovernanceProfile, ShellMode


class TestCeilingTable:
    def test_all_five_profiles_exist(self):
        assert len(CEILING_TABLE) == 5
        for p in GovernanceProfile:
            assert p in CEILING_TABLE

    def test_minimal_is_least_restrictive(self):
        c = CEILING_TABLE[GovernanceProfile.MINIMAL]
        assert c.auto_deploy is True
        assert c.db_write is True
        assert c.db_migration is True
        assert c.secrets_create is True
        assert c.max_session_duration_minutes is None
        assert c.agent_delegation is True

    def test_behoerde_is_most_restrictive(self):
        c = CEILING_TABLE[GovernanceProfile.BEHOERDE]
        assert c.auto_deploy is False
        assert c.db_write is False
        assert c.secrets_read is False
        assert c.agent_delegation is False
        assert c.min_approval_mode == ApprovalMode.FOUR_EYES
        assert c.max_session_duration_minutes == 30

    def test_enterprise_no_delegation(self):
        c = CEILING_TABLE[GovernanceProfile.ENTERPRISE]
        assert c.agent_delegation is False
        assert c.max_delegation_depth == 0


class TestGetCeiling:
    def test_by_enum(self):
        c = get_ceiling(GovernanceProfile.STANDARD)
        assert c.max_tool_calls == 500

    def test_by_string(self):
        c = get_ceiling("strict")
        assert c.shell_mode == ShellMode.ALLOWLIST

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            get_ceiling("nonexistent")


class TestListProfiles:
    def test_returns_five(self):
        profiles = list_profiles()
        assert len(profiles) == 5
        names = {p["name"] for p in profiles}
        assert "minimal" in names
        assert "behoerde" in names


class TestCeilingValidation:
    def test_valid_minimal(self):
        violations = validate_against_ceiling(
            "minimal",
            {"platform_permissions": {"auto_deploy": True, "db_write": True}},
            {"approval_mode": "autonomous"},
        )
        assert violations == []

    def test_auto_deploy_violation_standard(self):
        violations = validate_against_ceiling(
            "standard",
            {"platform_permissions": {"auto_deploy": True}},
            {"approval_mode": "supervised"},
        )
        assert len(violations) >= 1
        assert any(v["attribute"] == "auto_deploy" for v in violations)

    def test_session_duration_violation(self):
        violations = validate_against_ceiling(
            "standard",
            {"platform_permissions": {}},
            {
                "approval_mode": "supervised",
                "session_limits": {"max_session_duration_minutes": 500},
            },
        )
        assert any(v["attribute"] == "max_session_duration_minutes" for v in violations)

    def test_approval_mode_violation_behoerde(self):
        violations = validate_against_ceiling(
            "behoerde",
            {"platform_permissions": {}},
            {"approval_mode": "autonomous"},
        )
        assert any(v["attribute"] == "min_approval_mode" for v in violations)

    def test_multiple_violations_collected(self):
        violations = validate_against_ceiling(
            "enterprise",
            {"platform_permissions": {"auto_deploy": True, "db_write": True, "secrets_read": True}},
            {"approval_mode": "autonomous"},
        )
        assert len(violations) >= 3
