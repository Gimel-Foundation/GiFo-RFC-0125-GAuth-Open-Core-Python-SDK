"""Tests for the PEP evaluation engine."""

import pytest
from datetime import datetime, timedelta, timezone

from gauth_core.pep.engine import PEPEngine
from gauth_core.storage.memory import InMemoryMandateRepository


def _valid_credential(**overrides):
    base = {
        "mandate_id": "mdt_test123",
        "subject": "agent_1",
        "governance_profile": "minimal",
        "phase": "build",
        "core_verbs": {
            "file.read": {"allowed": True},
            "file.write": {"allowed": True},
            "shell.execute": {"allowed": False},
        },
        "platform_permissions": {"auto_deploy": False, "db_write": True},
        "allowed_paths": ["src/", "tests/"],
        "denied_paths": [".env", "secrets/"],
        "allowed_sectors": [],
        "allowed_regions": [],
        "approval_mode": "autonomous",
        "budget_total_cents": 10000,
        "budget_remaining_cents": 5000,
        "ttl_seconds": 43200,
        "scope_checksum": "sha256:abc123",
        "tool_permissions_hash": "sha256:def456",
        "platform_permissions_hash": "sha256:ghi789",
        "exp": (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(),
        "nbf": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "status": "ACTIVE",
        "delegation_chain": [],
        "session_limits": {"max_tool_calls": 500, "max_session_duration_minutes": 240},
    }
    base.update(overrides)
    return base


def _action(verb="file.read", resource="src/main.py", **params):
    return {"verb": verb, "resource": resource, "parameters": params}


def _context(agent_id="agent_1", **kwargs):
    return {"agent_id": agent_id, "timestamp": datetime.now(timezone.utc).isoformat(), **kwargs}


@pytest.fixture
def engine():
    return PEPEngine()


class TestPermitDecision:
    def test_basic_permit(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("file.read", "src/main.py"),
            context=_context(),
        )
        assert result["decision"] == "PERMIT"
        assert len(result["checks"]) >= 16
        assert result["audit"]["pep_interface_version"] == "1.1"

    def test_permit_includes_audit(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action(),
            context=_context(),
        )
        audit = result["audit"]
        assert "processing_time_ms" in audit
        assert audit["enforcement_mode"] in ("stateless", "stateful")
        assert audit["checks_evaluated"] >= 16


class TestDenyDecision:
    def test_denied_path(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("file.read", ".env"),
            context=_context(),
        )
        assert result["decision"] == "DENY"
        violations = result["violations"]
        assert any(v["violation_code"] == "PATH_DENIED" for v in violations)

    def test_denied_verb(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("shell.execute", "src/script.sh"),
            context=_context(),
        )
        assert result["decision"] == "DENY"

    def test_expired_credential(self, engine):
        cred = _valid_credential(
            exp=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        )
        result = engine.enforce_action(
            credential=cred,
            action=_action(),
            context=_context(),
        )
        assert result["decision"] == "DENY"

    def test_agent_mismatch(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action(),
            context=_context(agent_id="wrong_agent"),
        )
        assert result["decision"] == "DENY"

    def test_path_not_allowed(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("file.read", "config/database.yml"),
            context=_context(),
        )
        assert result["decision"] == "DENY"
        assert any(v["violation_code"] == "PATH_NOT_ALLOWED" for v in result["violations"])

    def test_budget_exhausted(self, engine):
        cred = _valid_credential(budget_remaining_cents=0)
        result = engine.enforce_action(
            credential=cred,
            action=_action(),
            context=_context(),
        )
        assert result["decision"] == "DENY"

    def test_session_tool_calls_exceeded(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action(),
            context=_context(session_tool_calls=500),
        )
        assert result["decision"] == "DENY"

    def test_unknown_profile(self, engine):
        cred = _valid_credential(governance_profile="nonexistent")
        result = engine.enforce_action(
            credential=cred,
            action=_action(),
            context=_context(),
        )
        assert result["decision"] == "DENY"

    def test_missing_credential_fields(self, engine):
        result = engine.enforce_action(
            credential={},
            action=_action(),
            context=_context(agent_id=""),
        )
        assert result["decision"] == "DENY"


class TestConstrainDecision:
    def test_approval_required_becomes_constrain(self):
        repo = InMemoryMandateRepository()
        repo.create({
            "mandate_id": "mdt_test123",
            "status": "ACTIVE",
            "parties": {"subject": "agent_1", "customer_id": "c", "project_id": "p", "issued_by": "u"},
            "scope": {
                "governance_profile": "standard",
                "core_verbs": {"file.write": {"allowed": True, "requires_approval": True}},
            },
            "requirements": {},
            "budget_state": {"total_cents": 10000, "remaining_cents": 5000, "consumed_cents": 5000},
        })
        engine = PEPEngine(repository=repo)
        cred = _valid_credential(
            approval_mode="supervised",
            core_verbs={
                "file.write": {"allowed": True, "requires_approval": True},
            },
        )
        result = engine.enforce_action(
            credential=cred,
            action=_action("file.write", "src/main.py"),
            context=_context(enforcement_mode="stateful"),
        )
        assert result["decision"] in ("CONSTRAIN", "PERMIT")


class TestAllChecksExecuted:
    def test_all_16_checks_run_even_after_failure(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("file.read", ".env"),
            context=_context(),
        )
        check_ids = {c["check_id"] for c in result["checks"]}
        for i in range(1, 17):
            assert f"CHK-{i:02d}" in check_ids


class TestDelegationTwoPass:
    def test_delegation_chain_narrowing(self, engine):
        cred = _valid_credential(
            delegation_chain=[
                {
                    "delegator": "root_agent",
                    "delegate": "agent_1",
                    "scope_restriction": {
                        "allowed_paths": ["src/"],
                    },
                    "delegated_at": datetime.now(timezone.utc).isoformat(),
                    "max_depth_remaining": 0,
                },
            ],
        )
        result = engine.enforce_action(
            credential=cred,
            action=_action("file.read", "src/main.py"),
            context=_context(),
        )
        assert result["decision"] == "PERMIT"
        assert result.get("effective_scope") is not None

    def test_delegation_depth_violation(self, engine):
        cred = _valid_credential(
            delegation_chain=[
                {
                    "delegator": "a",
                    "delegate": "b",
                    "scope_restriction": {},
                    "delegated_at": datetime.now(timezone.utc).isoformat(),
                    "max_depth_remaining": 1,
                },
                {
                    "delegator": "b",
                    "delegate": "agent_1",
                    "scope_restriction": {},
                    "delegated_at": datetime.now(timezone.utc).isoformat(),
                    "max_depth_remaining": 5,
                },
            ],
        )
        result = engine.enforce_action(
            credential=cred,
            action=_action(),
            context=_context(),
        )
        assert result["decision"] == "DENY"


class TestFailClosed:
    def test_stateful_no_repo_denies(self):
        engine = PEPEngine(repository=None)
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action(),
            context=_context(enforcement_mode="stateful"),
        )
        assert result["decision"] == "DENY"
        assert any(v["violation_code"] == "STATEFUL_MANDATE_NOT_FOUND" for v in result["violations"])

    def test_stateful_missing_mandate_denies(self):
        repo = InMemoryMandateRepository()
        engine = PEPEngine(repository=repo)
        result = engine.enforce_action(
            credential=_valid_credential(mandate_id="mdt_nonexistent"),
            action=_action(),
            context=_context(enforcement_mode="stateful"),
        )
        assert result["decision"] == "DENY"
        assert any(v["violation_code"] == "STATEFUL_MANDATE_NOT_FOUND" for v in result["violations"])

    def test_stateful_empty_mandate_id_denies(self):
        repo = InMemoryMandateRepository()
        engine = PEPEngine(repository=repo)
        result = engine.enforce_action(
            credential=_valid_credential(mandate_id=""),
            action=_action(),
            context=_context(enforcement_mode="stateful"),
        )
        assert result["decision"] == "DENY"


class TestModeSelection:
    def test_read_action_stateless(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action("file.read", "src/main.py"),
            context=_context(),
        )
        assert result["audit"]["enforcement_mode"] == "stateless"

    def test_behoerde_always_stateful(self, engine):
        cred = _valid_credential(governance_profile="behoerde")
        result = engine.enforce_action(
            credential=cred,
            action=_action("file.read", "src/main.py"),
            context=_context(),
        )
        assert result["audit"]["enforcement_mode"] == "stateful"

    def test_explicit_mode_override(self, engine):
        result = engine.enforce_action(
            credential=_valid_credential(),
            action=_action(),
            context=_context(enforcement_mode="stateful"),
        )
        assert result["audit"]["enforcement_mode"] == "stateful"


class TestBatchEnforce:
    def test_batch(self, engine):
        requests = [
            {
                "request_id": "r1",
                "credential": _valid_credential(),
                "action": _action("file.read", "src/a.py"),
                "context": _context(),
            },
            {
                "request_id": "r2",
                "credential": _valid_credential(),
                "action": _action("file.read", ".env"),
                "context": _context(),
            },
        ]
        results = engine.batch_enforce(requests)
        assert len(results) == 2
        assert results[0]["decision"] == "PERMIT"
        assert results[1]["decision"] == "DENY"


class TestEnforcementPolicy:
    def test_policy(self, engine):
        policy = engine.get_enforcement_policy()
        assert len(policy["supported_checks"]) == 16
        assert policy["fail_mode"] == "closed"
        assert policy["delegation_evaluation"] == "two_pass"


class TestHealth:
    def test_health(self, engine):
        health = engine.health()
        assert health["status"] == "ok"
        assert health["pep_interface_version"] == "1.1"
