"""Tests for the Management Service — mandate lifecycle operations."""

import pytest

from gauth_core.mgmt.service import MandateManagementService, ManagementError
from gauth_core.schema.enums import ManagementErrorCode, MandateStatus
from gauth_core.storage.memory import InMemoryMandateRepository


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
            "budget": {"total_cents": 10000},
            "ttl_seconds": 43200,
        },
    }


@pytest.fixture
def service():
    return MandateManagementService(InMemoryMandateRepository())


class TestCreateMandate:
    def test_creates_draft(self, service):
        result = service.create_mandate(_valid_mandate_data())
        assert result["status"] == "DRAFT"
        assert result["mandate_id"].startswith("mdt_")
        assert result["scope_checksum"].startswith("sha256:")
        assert result["validation"]["accepted"] is True

    def test_invalid_data_raises(self, service):
        with pytest.raises(ManagementError) as exc_info:
            service.create_mandate({"parties": {}, "scope": {}, "requirements": {}})
        assert exc_info.value.code == ManagementErrorCode.SCHEMA_VALIDATION_FAILED


class TestActivateMandate:
    def test_activate_draft(self, service):
        created = service.create_mandate(_valid_mandate_data())
        mid = created["mandate_id"]
        result = service.activate_mandate(mid, "user_1")
        assert result["status"] == "ACTIVE"
        assert result["activated_at"] is not None
        assert result["expires_at"] is not None

    def test_activate_nonexistent(self, service):
        with pytest.raises(ManagementError) as exc_info:
            service.activate_mandate("mdt_fake", "user_1")
        assert exc_info.value.code == ManagementErrorCode.MANDATE_NOT_FOUND

    def test_activate_already_active(self, service):
        created = service.create_mandate(_valid_mandate_data())
        mid = created["mandate_id"]
        service.activate_mandate(mid, "user_1")
        with pytest.raises(ManagementError) as exc_info:
            service.activate_mandate(mid, "user_1")
        assert exc_info.value.code == ManagementErrorCode.MANDATE_NOT_DRAFT

    def test_supersedes_existing(self, service):
        d1 = _valid_mandate_data()
        c1 = service.create_mandate(d1)
        service.activate_mandate(c1["mandate_id"], "user_1")

        d2 = _valid_mandate_data()
        c2 = service.create_mandate(d2)
        result = service.activate_mandate(c2["mandate_id"], "user_1")
        assert result["superseded_mandate_id"] == c1["mandate_id"]


class TestRevokeMandate:
    def test_revoke_active(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.revoke_mandate(created["mandate_id"], "user_1", "test reason")
        assert result["status"] == "REVOKED"
        assert result["reason"] == "test reason"

    def test_revoke_terminal_fails(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        service.revoke_mandate(created["mandate_id"], "user_1", "first")
        with pytest.raises(ManagementError):
            service.revoke_mandate(created["mandate_id"], "user_1", "second")


class TestSuspendResume:
    def test_suspend_active(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.suspend_mandate(created["mandate_id"], "user_1", "investigation")
        assert result["status"] == "SUSPENDED"

    def test_resume_suspended(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        service.suspend_mandate(created["mandate_id"], "user_1", "investigation")
        result = service.resume_mandate(created["mandate_id"], "user_1", "cleared")
        assert result["status"] == "ACTIVE"
        assert result["remaining_ttl_seconds"] > 0

    def test_suspend_draft_fails(self, service):
        created = service.create_mandate(_valid_mandate_data())
        with pytest.raises(ManagementError) as exc_info:
            service.suspend_mandate(created["mandate_id"], "user_1", "reason")
        assert exc_info.value.code == ManagementErrorCode.MANDATE_NOT_ACTIVE

    def test_revoke_suspended(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        service.suspend_mandate(created["mandate_id"], "user_1", "investigation")
        result = service.revoke_mandate(created["mandate_id"], "user_1", "confirmed threat")
        assert result["status"] == "REVOKED"


class TestBudget:
    def test_increase_additive_only(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.increase_budget(created["mandate_id"], 5000, "user_1")
        assert result["new_total_cents"] == 15000
        assert result["remaining_cents"] == 15000

    def test_consume_budget(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.consume_budget(
            created["mandate_id"], "req_001", 3000, "file.write", "src/main.py",
        )
        assert result["accepted"] is True
        assert result["remaining_cents"] == 7000

    def test_consume_idempotent(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        service.consume_budget(created["mandate_id"], "req_001", 3000, "file.write", "src/main.py")
        result = service.consume_budget(created["mandate_id"], "req_001", 3000, "file.write", "src/main.py")
        assert result["accepted"] is True

    def test_consume_negative_rejected(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        with pytest.raises(ManagementError) as exc_info:
            service.consume_budget(
                created["mandate_id"], "req_neg", -100, "file.write", "src/main.py",
            )
        assert exc_info.value.code == ManagementErrorCode.BUDGET_DECREASE_NOT_ALLOWED

    def test_consume_zero_rejected(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        with pytest.raises(ManagementError):
            service.consume_budget(
                created["mandate_id"], "req_zero", 0, "file.write", "src/main.py",
            )

    def test_budget_exhaustion(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.consume_budget(
            created["mandate_id"], "req_full", 10000, "file.write", "src/main.py",
        )
        assert result["budget_exceeded"] is True
        mandate = service.get_mandate(created["mandate_id"])
        assert mandate["status"] == "BUDGET_EXCEEDED"


class TestTTL:
    def test_extend_additive(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.extend_ttl(created["mandate_id"], 3600, "user_1")
        assert result["new_ttl_seconds"] == 43200 + 3600


class TestDelegation:
    def test_create_delegation(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.create_delegation(
            created["mandate_id"],
            "sub_agent_1",
            {"phase": "build"},
            2000,
            3600,
            "agent_1",
        )
        assert result["status"] == "ACTIVE"
        assert result["delegation_depth"] == 1
        assert result["budget_cents"] == 2000

    def test_delegation_budget_exceeded(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        with pytest.raises(ManagementError) as exc_info:
            service.create_delegation(
                created["mandate_id"], "sub_agent", {}, 50000, 3600, "agent_1",
            )
        assert exc_info.value.code == ManagementErrorCode.DELEGATION_BUDGET_EXCEEDED

    def test_delegation_budget_reservation_persisted(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        service.create_delegation(
            created["mandate_id"], "sub_agent_1", {}, 4000, 3600, "agent_1",
        )
        service.create_delegation(
            created["mandate_id"], "sub_agent_2", {}, 4000, 3600, "agent_1",
        )
        with pytest.raises(ManagementError) as exc_info:
            service.create_delegation(
                created["mandate_id"], "sub_agent_3", {}, 4000, 3600, "agent_1",
            )
        assert exc_info.value.code == ManagementErrorCode.DELEGATION_BUDGET_EXCEEDED

    def test_delegation_scope_narrowing(self, service):
        data = _valid_mandate_data()
        data["scope"]["allowed_paths"] = ["src/", "tests/"]
        created = service.create_mandate(data)
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.create_delegation(
            created["mandate_id"],
            "sub_agent",
            {"allowed_paths": ["src/", "docs/"]},
            2000,
            3600,
            "agent_1",
        )
        child = service.get_mandate(result["mandate_id"])
        assert child["scope"]["allowed_paths"] == ["src/"]

    def test_delegation_platform_permissions_narrowed(self, service):
        data = _valid_mandate_data()
        data["scope"]["platform_permissions"] = {
            "auto_deploy": True,
            "db_write": True,
            "db_production": False,
        }
        created = service.create_mandate(data)
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.create_delegation(
            created["mandate_id"],
            "sub_agent",
            {"platform_permissions": {"auto_deploy": True, "db_write": False, "db_production": True}},
            2000,
            3600,
            "agent_1",
        )
        child = service.get_mandate(result["mandate_id"])
        pp = child["scope"]["platform_permissions"]
        assert pp["auto_deploy"] is True
        assert pp["db_write"] is False
        assert pp["db_production"] is False

    def test_delegation_ignores_unknown_scope_keys(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.create_delegation(
            created["mandate_id"],
            "sub_agent",
            {"nonexistent_key": "some_value"},
            2000,
            3600,
            "agent_1",
        )
        child = service.get_mandate(result["mandate_id"])
        assert "nonexistent_key" not in child["scope"]

    def test_cascade_revocation(self, service):
        parent = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(parent["mandate_id"], "user_1")
        child = service.create_delegation(
            parent["mandate_id"], "sub_agent", {}, 2000, 3600, "agent_1",
        )
        result = service.revoke_mandate(parent["mandate_id"], "user_1", "security")
        assert child["mandate_id"] in result["cascaded_revocations"]


class TestQueryOperations:
    def test_get_mandate(self, service):
        created = service.create_mandate(_valid_mandate_data())
        result = service.get_mandate(created["mandate_id"])
        assert result["mandate_id"] == created["mandate_id"]

    def test_list_mandates(self, service):
        service.create_mandate(_valid_mandate_data())
        service.create_mandate(_valid_mandate_data())
        result = service.list_mandates()
        assert result["total_count"] == 2

    def test_get_history(self, service):
        created = service.create_mandate(_valid_mandate_data())
        result = service.get_history(created["mandate_id"])
        assert len(result["history"]) >= 1

    def test_get_budget_state(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        result = service.get_budget_state(created["mandate_id"])
        assert result["total_cents"] == 10000
        assert result["remaining_cents"] == 10000

    def test_delete_draft(self, service):
        created = service.create_mandate(_valid_mandate_data())
        result = service.delete_draft(created["mandate_id"])
        assert result["deleted"] is True

    def test_delete_active_fails(self, service):
        created = service.create_mandate(_valid_mandate_data())
        service.activate_mandate(created["mandate_id"], "user_1")
        with pytest.raises(ManagementError) as exc_info:
            service.delete_draft(created["mandate_id"])
        assert exc_info.value.code == ManagementErrorCode.MANDATE_NOT_DRAFT


class TestProfiles:
    def test_list_profiles(self, service):
        profiles = service.get_profiles()
        assert len(profiles) == 5

    def test_get_profile_ceilings(self, service):
        result = service.get_profile_ceilings("standard")
        assert result["profile"] == "standard"
        assert "max_tool_calls" in result["ceilings"]

    def test_unknown_profile_raises(self, service):
        with pytest.raises(ManagementError) as exc_info:
            service.get_profile_ceilings("unknown")
        assert exc_info.value.code == ManagementErrorCode.PROFILE_NOT_FOUND
