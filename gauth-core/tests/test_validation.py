"""Tests for the three-stage validation pipeline."""

import pytest

from gauth_core.validation.pipeline import (
    validate_consistency,
    validate_mandate,
    validate_schema,
    validate_ceilings,
)


def _valid_mandate_data():
    return {
        "parties": {
            "subject": "agent_1",
            "customer_id": "cust_1",
            "project_id": "proj_1",
            "issued_by": "user_1",
        },
        "scope": {
            "governance_profile": "minimal",
            "phase": "build",
        },
        "requirements": {
            "approval_mode": "autonomous",
            "budget": {"total_cents": 5000},
            "ttl_seconds": 3600,
        },
    }


class TestSchemaValidation:
    def test_valid(self):
        parsed, errors = validate_schema(_valid_mandate_data())
        assert parsed is not None
        assert errors == []

    def test_missing_parties(self):
        data = _valid_mandate_data()
        del data["parties"]
        parsed, errors = validate_schema(data)
        assert parsed is None
        assert len(errors) > 0


class TestCeilingValidation:
    def test_valid_minimal(self):
        violations = validate_ceilings(
            {"governance_profile": "minimal", "platform_permissions": {}},
            {"approval_mode": "autonomous"},
        )
        assert violations == []

    def test_unknown_profile(self):
        violations = validate_ceilings(
            {"governance_profile": "unknown"},
            {"approval_mode": "autonomous"},
        )
        assert len(violations) == 1
        assert violations[0]["code"] == "PROFILE_NOT_FOUND"


class TestConsistencyChecks:
    def test_c1_four_eyes_missing_approvers(self):
        errors = validate_consistency(
            {},
            {"approval_mode": "four-eyes"},
            {"approval_chain": ["user_1"]},
        )
        assert any(e["rule"] == "C-1" for e in errors)

    def test_c1_four_eyes_valid(self):
        errors = validate_consistency(
            {},
            {"approval_mode": "four-eyes"},
            {"approval_chain": ["user_1", "user_2"]},
        )
        assert not any(e["rule"] == "C-1" for e in errors)

    def test_c2_path_conflict(self):
        errors = validate_consistency(
            {"allowed_paths": ["src/", "config/"], "denied_paths": ["src/"]},
            {"approval_mode": "autonomous", "budget": {"total_cents": 100}, "ttl_seconds": 120},
            {},
        )
        assert any(e["rule"] == "C-2" for e in errors)

    def test_c3_negative_budget(self):
        errors = validate_consistency(
            {},
            {"approval_mode": "autonomous", "budget": {"total_cents": -5}, "ttl_seconds": 120},
            {},
        )
        assert any(e["rule"] == "C-3" for e in errors)

    def test_c4_ttl_too_short(self):
        errors = validate_consistency(
            {},
            {"approval_mode": "autonomous", "budget": {"total_cents": 100}, "ttl_seconds": 30},
            {},
        )
        assert any(e["rule"] == "C-4" for e in errors)

    def test_no_errors_valid(self):
        errors = validate_consistency(
            {"allowed_paths": ["src/"], "denied_paths": [".env"]},
            {"approval_mode": "autonomous", "budget": {"total_cents": 100}, "ttl_seconds": 120},
            {},
        )
        assert errors == []


class TestFullPipeline:
    def test_valid_mandate(self):
        result = validate_mandate(_valid_mandate_data())
        assert result.accepted is True
        assert result.schema_errors == []
        assert result.ceiling_violations == []
        assert result.consistency_errors == []

    def test_multiple_failures(self):
        data = _valid_mandate_data()
        data["scope"]["governance_profile"] = "standard"
        data["scope"]["platform_permissions"] = {"auto_deploy": True}
        data["requirements"]["approval_mode"] = "autonomous"
        result = validate_mandate(data)
        assert result.accepted is False
