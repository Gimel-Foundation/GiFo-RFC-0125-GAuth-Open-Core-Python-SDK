"""Conformance tests for Gap Spec Block B — G-03 through G-07.

Test IDs follow the Gap Specification v1.2.0 §4.2 naming:
  CT-REG-024–027   New adapter registry slots
  CT-PEP-032–039   OAuth pre-check + CHK-09 full constraint evaluation
  CT-MGMT-027–030  Delegation approval gate + PoA map
  CT-CF-001–019    W3C VC translation layer conformance
"""

import os
import hashlib
import hmac as hmac_mod
import json
import time

import pytest

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    ComplianceEnrichmentAdapter,
    DnaIdentityAdapter,
    GovernanceAdapter,
    OAuthEngineAdapter,
    RegulatoryReasoningAdapter,
    RiskScoringAdapter,
    WalletAdapter,
    Web3IdentityAdapter,
)
from gauth_core.adapters.defaults import (
    NoOpDnaIdentityAdapter,
    NoOpGovernanceAdapter,
    NoOpOAuthEngineAdapter,
    NoOpWalletAdapter,
    NoOpWeb3IdentityAdapter,
)
from gauth_core.adapters.registry import (
    ADAPTER_BASE_TYPES,
    MANDATORY_SLOTS,
    NOOP_CLASSES,
    SLOT_TO_ADAPTER_TYPE,
    AdapterRegistrationError,
    AdapterRegistry,
    _is_noop,
)
from gauth_core.mgmt.service import ManagementError, MandateManagementService
from gauth_core.pep.checks import (
    chk_09_constraints,
    narrow_constraints,
    KNOWN_CONSTRAINT_KEYS,
)
from gauth_core.pep.engine import PEPEngine
from gauth_core.profiles.ceilings import get_ceiling
from gauth_core.schema.enums import (
    Decision,
    EnforcementMode,
    ManagementErrorCode,
    MandateStatus,
    OperationType,
    Tariff,
)
from gauth_core.storage.memory import InMemoryMandateRepository
from gauth_core.vc.serializer import (
    create_data_integrity_proof,
    poa_to_vc,
    vc_to_jwt_payload,
    verify_data_integrity_proof,
)
from gauth_core.vc.did import create_did_key, resolve_did, resolve_did_key, resolve_did_web
from gauth_core.vc.status_list import BitstringStatusList
from gauth_core.vc.sd_jwt import create_sd_jwt, verify_sd_jwt_disclosures
from gauth_core.vc.openid import OpenID4VCIStub, OpenID4VPStub


def _make_license_token(body="test_body", secret="test_secret"):
    sig = hmac_mod.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"gimel_lic_{body}.{sig}"


def _make_repo_and_service():
    repo = InMemoryMandateRepository()
    svc = MandateManagementService(repo)
    return repo, svc


def _create_active_mandate(svc, profile="standard", approval_mode="supervised", budget=10000, ttl=7200):
    shell_mode = "denylist"
    if profile in ("strict", "enterprise", "behoerde"):
        shell_mode = "allowlist"

    if profile == "behoerde":
        approval_mode = "four-eyes"
    elif profile in ("standard", "strict", "enterprise") and approval_mode == "autonomous":
        pass

    data = {
        "parties": {
            "subject": "agent-1",
            "customer_id": "cust-1",
            "project_id": "proj-1",
            "issued_by": "admin",
            **({"approval_chain": ["approver-1", "approver-2"]} if approval_mode == "four-eyes" else {}),
        },
        "scope": {
            "governance_profile": profile,
            "phase": "build",
            "core_verbs": {
                "file.read": {"allowed": True},
                "file.write": {"allowed": True},
                "code.execute": {"allowed": True, "requires_approval": True},
            },
            "allowed_sectors": ["fintech", "health"],
            "allowed_regions": ["EU", "US"],
            "platform_permissions": {
                "auto_deploy": False,
                "db_write": profile in ("minimal", "standard", "strict"),
                "shell_mode": shell_mode,
            },
        },
        "requirements": {
            "approval_mode": approval_mode,
            "budget": {"total_cents": budget},
            "ttl_seconds": ttl,
        },
    }
    result = svc.create_mandate(data)
    mandate_id = result["mandate_id"]
    svc.activate_mandate(mandate_id, activated_by="admin")
    return mandate_id


class TestRegistryNewSlots:
    """CT-REG-024–027 — new adapter slots, NoOps, mandatory slots."""

    def test_ct_reg_024_adapter_base_types_has_all_9_slots(self):
        expected = {
            "ai_enrichment", "risk_scoring", "regulatory_reasoning",
            "compliance_enrichment", "oauth_engine", "governance",
            "web3_identity", "dna_identity", "wallet",
        }
        assert set(ADAPTER_BASE_TYPES.keys()) == expected

    def test_ct_reg_025_noop_classes_has_all_9(self):
        expected = {
            "NoOpAIEnrichmentAdapter", "NoOpRiskScoringAdapter",
            "NoOpRegulatoryReasoningAdapter", "NoOpComplianceEnrichmentAdapter",
            "NoOpOAuthEngineAdapter", "NoOpGovernanceAdapter",
            "NoOpWeb3IdentityAdapter", "NoOpDnaIdentityAdapter",
            "NoOpWalletAdapter",
        }
        assert NOOP_CLASSES == expected

    def test_ct_reg_026_slot_to_adapter_type_mapping(self):
        assert SLOT_TO_ADAPTER_TYPE["ai_governance"] == "ai_enrichment"
        assert SLOT_TO_ADAPTER_TYPE["web3_identity"] == "risk_scoring"
        assert SLOT_TO_ADAPTER_TYPE["dna_identity"] == "regulatory_reasoning"
        assert SLOT_TO_ADAPTER_TYPE["pdp"] == "compliance_enrichment"
        assert SLOT_TO_ADAPTER_TYPE["oauth_engine"] == "oauth_engine"
        assert SLOT_TO_ADAPTER_TYPE["foundry"] == "governance"
        assert SLOT_TO_ADAPTER_TYPE["wallet"] == "wallet"
        assert len(SLOT_TO_ADAPTER_TYPE) == 7

    def test_ct_reg_027_mandatory_slot_oauth_engine_unregister_rejected(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            registry = AdapterRegistry(allow_untrusted=True)
            with pytest.raises(AdapterRegistrationError, match="mandatory"):
                registry.unregister("oauth_engine")
            assert "oauth_engine" in MANDATORY_SLOTS
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)


class TestRegistryNewAdapters:
    """CT-REG supplemental — registry initializes all new NoOps."""

    def test_registry_init_has_all_noop_adapters(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            reg = AdapterRegistry(allow_untrusted=True)
            assert _is_noop(reg.oauth_engine)
            assert _is_noop(reg.governance)
            assert _is_noop(reg.web3_identity)
            assert _is_noop(reg.dna_identity)
            assert _is_noop(reg.wallet)
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)

    def test_noop_oauth_engine_returns_noop_source(self):
        adapter = NoOpOAuthEngineAdapter()
        result = adapter.validate_token("any_token")
        assert result["source"] == "noop"

    def test_noop_governance_evaluate_returns_noop(self):
        adapter = NoOpGovernanceAdapter()
        result = adapter.evaluate_governance_policy({"mandate_id": "test"}, {"verb": "read"})
        assert result.get("source") == "noop"

    def test_noop_wallet_store_returns_noop(self):
        adapter = NoOpWalletAdapter()
        result = adapter.store_credential({"id": "test"})
        assert result.get("source") == "noop"


class TestPEPOAuthPreCheck:
    """CT-PEP-032–035 — OAuth pre-check before 16-check pipeline."""

    def _make_oauth_adapter(self, active=True):
        class _TestOAuth(OAuthEngineAdapter):
            ADAPTER_TYPE = "oauth_engine"
            def issue_token(self, grant_type, client_id, scope=None, claims=None):
                return {"access_token": "tok", "source": "test"}
            def validate_token(self, token):
                return {"active": active, "token": token}
            def revoke_token(self, token, token_type_hint="access_token"):
                return {"revoked": True}
            def get_jwks(self):
                return {"keys": []}
            def introspect(self, token):
                return {"active": active}
            def before_token_issuance(self, context):
                return context
            def after_token_issuance(self, token_response, context):
                return token_response
            def health_check(self):
                return True
        return _TestOAuth()

    def test_ct_pep_032_oauth_precheck_deny_on_inactive_token(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            reg = AdapterRegistry(allow_untrusted=True)
            reg.register(self._make_oauth_adapter(active=False), adapter_type="oauth_engine")

            engine = PEPEngine(adapter_registry=reg)
            result = engine.enforce_action(
                credential={"mandate_id": "m1", "subject": "a1", "governance_profile": "minimal",
                             "phase": "build", "scope_checksum": "abc"},
                action={"verb": "file.read"},
                context={"oauth_token": "bad_token"},
            )
            assert result["decision"] == Decision.DENY.value
            assert any(c["violation_code"] == "OAUTH_TOKEN_INVALID" for c in result["checks"])
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)

    def test_ct_pep_033_oauth_precheck_passes_on_active_token(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            reg = AdapterRegistry(allow_untrusted=True)
            reg.register(self._make_oauth_adapter(active=True), adapter_type="oauth_engine")

            engine = PEPEngine(adapter_registry=reg)
            result = engine.enforce_action(
                credential={"mandate_id": "m1", "subject": "a1", "governance_profile": "minimal",
                             "phase": "build", "scope_checksum": "abc"},
                action={"verb": "file.read"},
                context={"oauth_token": "good_token"},
            )
            assert result["decision"] != Decision.DENY.value or not any(
                c.get("violation_code") == "OAUTH_TOKEN_INVALID" for c in result["checks"]
            )
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)

    def test_ct_pep_034_oauth_precheck_skipped_when_noop(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            reg = AdapterRegistry(allow_untrusted=True)
            engine = PEPEngine(adapter_registry=reg)
            result = engine.enforce_action(
                credential={"mandate_id": "m1", "subject": "a1", "governance_profile": "minimal",
                             "phase": "build", "scope_checksum": "abc"},
                action={"verb": "file.read"},
                context={"oauth_token": "any_token"},
            )
            assert not any(c.get("violation_code") == "OAUTH_TOKEN_INVALID" for c in result["checks"])
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)

    def test_ct_pep_035_oauth_precheck_skipped_when_no_token(self):
        os.environ["GAUTH_DEV_MODE"] = "true"
        try:
            reg = AdapterRegistry(allow_untrusted=True)
            reg.register(self._make_oauth_adapter(active=False), adapter_type="oauth_engine")
            engine = PEPEngine(adapter_registry=reg)
            result = engine.enforce_action(
                credential={"mandate_id": "m1", "subject": "a1", "governance_profile": "minimal",
                             "phase": "build", "scope_checksum": "abc"},
                action={"verb": "file.read"},
                context={},
            )
            assert not any(c.get("violation_code") == "OAUTH_TOKEN_INVALID" for c in result["checks"])
        finally:
            os.environ.pop("GAUTH_DEV_MODE", None)


class TestPEPConstraints:
    """CT-PEP-036–039 — CHK-09 full constraint evaluation."""

    def _make_credential(self, verb="shell.exec", constraints=None):
        return {
            "mandate_id": "m1",
            "subject": "a1",
            "governance_profile": "standard",
            "phase": "build",
            "scope_checksum": "abc",
            "core_verbs": {
                verb: {"allowed": True, "constraints": constraints or {}},
            },
        }

    def test_ct_pep_036_denied_commands_blocks_rm(self):
        cred = self._make_credential(
            constraints={"denied_commands": ["rm", "dd", "mkfs"]}
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "rm"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "fail"
        assert result["violation_code"] == "CONSTRAINT_VIOLATED"
        assert "denied_commands" in result["details"].get("constraint_key", "")

    def test_ct_pep_036b_denied_commands_allows_ls(self):
        cred = self._make_credential(
            constraints={"denied_commands": ["rm", "dd", "mkfs"]}
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "ls"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "pass"

    def test_ct_pep_037_allowed_commands_blocks_unapproved(self):
        cred = self._make_credential(
            constraints={"allowed_commands": ["git", "npm", "node"]}
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "curl"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "fail"
        assert result["violation_code"] == "CONSTRAINT_VIOLATED"

    def test_ct_pep_037b_allowed_commands_permits_approved(self):
        cred = self._make_credential(
            constraints={"allowed_commands": ["git", "npm", "node"]}
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "git"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "pass"

    def test_ct_pep_038_path_patterns_blocks_outside(self):
        cred = self._make_credential(
            verb="file.write",
            constraints={"path_patterns": ["src/**", "tests/**"]},
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "file.write", "resource": "/etc/passwd", "parameters": {}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "fail"

    def test_ct_pep_038b_path_patterns_allows_matching(self):
        cred = self._make_credential(
            verb="file.write",
            constraints={"path_patterns": ["src/**", "tests/**"]},
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "file.write", "resource": "src/main.py", "parameters": {}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "pass"

    def test_ct_pep_039_max_file_size_blocks_large(self):
        cred = self._make_credential(
            verb="file.write",
            constraints={"max_file_size_bytes": 1048576},
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "file.write", "resource": "big.bin",
                     "parameters": {"file_size_bytes": 2000000}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "fail"
        assert result["violation_code"] == "CONSTRAINT_VIOLATED"

    def test_ct_pep_039b_max_delegation_depth_blocks(self):
        cred = self._make_credential(
            constraints={"max_delegation_depth": 2}
        )
        cred["delegation_chain"] = [{"delegate": "a"}, {"delegate": "b"}, {"delegate": "c"}]
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "ls"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "fail"

    def test_ct_pep_039c_unknown_constraint_key_does_not_deny(self):
        cred = self._make_credential(
            constraints={"unknown_future_key": "whatever", "denied_commands": []}
        )
        result = chk_09_constraints(
            credential=cred,
            action={"verb": "shell.exec", "parameters": {"command": "ls"}},
            mode=EnforcementMode.STATEFUL,
            live_mandate={"scope": {"core_verbs": cred["core_verbs"]}},
        )
        assert result["result"] == "pass"

    def test_ct_pep_039d_known_constraint_keys_frozenset(self):
        assert "path_patterns" in KNOWN_CONSTRAINT_KEYS
        assert "allowed_commands" in KNOWN_CONSTRAINT_KEYS
        assert "denied_commands" in KNOWN_CONSTRAINT_KEYS
        assert "max_delegation_depth" in KNOWN_CONSTRAINT_KEYS
        assert "max_file_size_bytes" in KNOWN_CONSTRAINT_KEYS
        assert len(KNOWN_CONSTRAINT_KEYS) == 5


class TestNarrowConstraints:
    """CT-PEP supplemental — narrow_constraints() helper."""

    def test_narrow_intersects_allowed_commands(self):
        parent = {"allowed_commands": ["git", "npm", "node"]}
        child = {"allowed_commands": ["git", "docker"]}
        result = narrow_constraints(parent, child)
        assert result["allowed_commands"] == ["git"]

    def test_narrow_unions_denied_commands(self):
        parent = {"denied_commands": ["rm"]}
        child = {"denied_commands": ["dd"]}
        result = narrow_constraints(parent, child)
        assert set(result["denied_commands"]) == {"rm", "dd"}

    def test_narrow_takes_min_depth(self):
        parent = {"max_delegation_depth": 3}
        child = {"max_delegation_depth": 1}
        result = narrow_constraints(parent, child)
        assert result["max_delegation_depth"] == 1

    def test_narrow_takes_min_file_size(self):
        parent = {"max_file_size_bytes": 1048576}
        child = {"max_file_size_bytes": 524288}
        result = narrow_constraints(parent, child)
        assert result["max_file_size_bytes"] == 524288


class TestDelegationApprovalGate:
    """CT-MGMT-027–030 — delegation approval gate."""

    def test_ct_mgmt_027_delegation_with_supervised_requires_approval(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="supervised")

        result = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={"allowed_sectors": ["fintech"]},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        assert result["status"] == MandateStatus.PENDING_APPROVAL.value
        assert result["approval_required"] is True
        assert result["required_approvers"] == 1

    def test_ct_mgmt_027b_delegation_with_four_eyes_requires_2_approvers(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="four-eyes")

        result = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={"allowed_sectors": ["fintech"]},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        assert result["status"] == MandateStatus.PENDING_APPROVAL.value
        assert result["required_approvers"] == 2

    def test_ct_mgmt_028_approve_delegation_activates(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="supervised")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]

        approval = svc.approve_delegation(child_id, approved_by="approver-1")
        assert approval["status"] == MandateStatus.ACTIVE.value
        assert approval["fully_approved"] is True
        assert approval["activated_at"] is not None

    def test_ct_mgmt_028b_four_eyes_needs_two_approvals(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="four-eyes")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]

        first = svc.approve_delegation(child_id, approved_by="approver-1")
        assert first["fully_approved"] is False
        assert first["remaining_approvers"] == 1

        second = svc.approve_delegation(child_id, approved_by="approver-2")
        assert second["fully_approved"] is True
        assert second["status"] == MandateStatus.ACTIVE.value

    def test_ct_mgmt_028c_duplicate_approval_rejected(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="four-eyes")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]
        svc.approve_delegation(child_id, approved_by="approver-1")

        with pytest.raises(ManagementError) as exc:
            svc.approve_delegation(child_id, approved_by="approver-1")
        assert exc.value.code == ManagementErrorCode.DELEGATION_ALREADY_APPROVED

    def test_ct_mgmt_029_reject_delegation_deletes(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="supervised")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]

        rejection = svc.reject_delegation(child_id, rejected_by="approver-1", reason="not allowed")
        assert rejection["status"] == MandateStatus.DELETED.value
        assert rejection["rejected_by"] == "approver-1"
        assert rejection["reason"] == "not allowed"

    def test_ct_mgmt_029b_reject_releases_parent_budget(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="standard", approval_mode="supervised", budget=10000)

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=2000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]

        parent_before = repo.get(mandate_id)
        reserved_before = parent_before["budget_state"]["reserved_for_delegations_cents"]
        assert reserved_before >= 2000

        svc.reject_delegation(child_id, rejected_by="approver-1")

        parent_after = repo.get(mandate_id)
        reserved_after = parent_after["budget_state"]["reserved_for_delegations_cents"]
        assert reserved_after < reserved_before

    def test_ct_mgmt_030_approve_non_pending_raises(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="minimal", approval_mode="autonomous")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]
        assert delegation["status"] == MandateStatus.ACTIVE.value

        with pytest.raises(ManagementError) as exc:
            svc.approve_delegation(child_id, approved_by="approver-1")
        assert exc.value.code == ManagementErrorCode.DELEGATION_NOT_PENDING

    def test_ct_mgmt_030b_reject_non_pending_raises(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc, profile="minimal", approval_mode="autonomous")

        delegation = svc.create_delegation(
            parent_mandate_id=mandate_id,
            delegate_agent_id="delegate-1",
            scope_restriction={},
            budget_cents=1000,
            ttl_seconds=3600,
            delegated_by="admin",
        )
        child_id = delegation["mandate_id"]

        with pytest.raises(ManagementError) as exc:
            svc.reject_delegation(child_id, rejected_by="approver-1")
        assert exc.value.code == ManagementErrorCode.DELEGATION_NOT_PENDING


class TestPoaMapSummary:
    """CT-MGMT supplemental — generate_poa_map()."""

    def test_poa_map_contains_required_fields(self):
        repo, svc = _make_repo_and_service()
        mandate_id = _create_active_mandate(svc)

        poa_map = svc.generate_poa_map(mandate_id)
        assert "mandate_id" in poa_map
        assert "governance_profile" in poa_map
        assert "permissions" in poa_map
        assert "allowed_actions" in poa_map
        assert "status" in poa_map
        assert "subject" in poa_map

    def test_poa_map_not_found_raises(self):
        repo, svc = _make_repo_and_service()
        with pytest.raises(ManagementError) as exc:
            svc.generate_poa_map("nonexistent")
        assert exc.value.code == ManagementErrorCode.MANDATE_NOT_FOUND


class TestProfileCeilingApproval:
    """CT-MGMT supplemental — approval_required_for_delegation in ceilings."""

    def test_minimal_does_not_require_approval(self):
        ceiling = get_ceiling("minimal")
        assert ceiling.approval_required_for_delegation is False

    def test_standard_requires_approval(self):
        ceiling = get_ceiling("standard")
        assert ceiling.approval_required_for_delegation is True

    def test_strict_requires_approval(self):
        ceiling = get_ceiling("strict")
        assert ceiling.approval_required_for_delegation is True

    def test_enterprise_no_delegation_at_all(self):
        ceiling = get_ceiling("enterprise")
        assert ceiling.agent_delegation is False

    def test_profile_ceilings_endpoint_includes_field(self):
        repo, svc = _make_repo_and_service()
        result = svc.get_profile_ceilings("standard")
        assert "approval_required_for_delegation" in result["ceilings"]
        assert result["ceilings"]["approval_required_for_delegation"] is True


class TestVCSerializerConformance:
    """CT-CF-001–005 — PoA → W3C VC Data Model v2.0 serialization."""

    def _make_mandate(self):
        return {
            "mandate_id": "mdt_test123",
            "status": "ACTIVE",
            "parties": {
                "subject": "agent-1",
                "customer_id": "cust-1",
                "project_id": "proj-1",
                "issued_by": "admin",
            },
            "scope": {
                "governance_profile": "standard",
                "phase": "build",
                "core_verbs": {
                    "file.read": {"allowed": True},
                    "file.write": {"allowed": True},
                    "deploy": {"allowed": False},
                },
                "allowed_sectors": ["fintech"],
                "allowed_regions": ["EU"],
                "allowed_decisions": ["approve"],
            },
            "requirements": {
                "approval_mode": "supervised",
                "budget": {"total_cents": 5000},
            },
            "budget_state": {
                "total_cents": 5000,
                "remaining_cents": 4500,
                "consumed_cents": 500,
            },
            "scope_checksum": "abc123",
            "tool_permissions_hash": "def456",
            "platform_permissions_hash": "ghi789",
            "activated_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-01-02T00:00:00+00:00",
        }

    def test_ct_cf_001_vc_has_w3c_v2_context(self):
        vc = poa_to_vc(self._make_mandate())
        assert "https://www.w3.org/ns/credentials/v2" in vc["@context"]

    def test_ct_cf_002_vc_has_gauth_context(self):
        vc = poa_to_vc(self._make_mandate())
        assert "https://gauth.gimel.foundation/credentials/v1" in vc["@context"]

    def test_ct_cf_003_vc_type_includes_gauth_poa(self):
        vc = poa_to_vc(self._make_mandate())
        assert "VerifiableCredential" in vc["type"]
        assert "GAuthPoACredential" in vc["type"]

    def test_ct_cf_004_vc_credential_subject_maps_fields(self):
        vc = poa_to_vc(self._make_mandate())
        cs = vc["credentialSubject"]
        assert cs["mandate_id"] == "mdt_test123"
        assert cs["governance_profile"] == "standard"
        assert cs["phase"] == "build"
        assert cs["approval_mode"] == "supervised"
        assert "file.read" in cs["allowed_actions"]
        assert "file.write" in cs["allowed_actions"]
        assert "deploy" not in cs["allowed_actions"]
        assert cs["allowed_sectors"] == ["fintech"]
        assert cs["allowed_regions"] == ["EU"]
        assert cs["budget_total_cents"] == 5000
        assert cs["budget_remaining_cents"] == 4500
        assert cs["scope_checksum"] == "abc123"

    def test_ct_cf_005_vc_issuer_is_did_web(self):
        vc = poa_to_vc(self._make_mandate())
        assert vc["issuer"]["id"].startswith("did:web:")

    def test_ct_cf_005b_vc_custom_issuer_did(self):
        vc = poa_to_vc(self._make_mandate(), issuer_did="did:web:custom.example.com")
        assert vc["issuer"]["id"] == "did:web:custom.example.com"

    def test_ct_cf_005c_vc_valid_from_and_until(self):
        vc = poa_to_vc(self._make_mandate())
        assert "validFrom" in vc
        assert "validUntil" in vc

    def test_ct_cf_005d_vc_status_list_entry(self):
        vc = poa_to_vc(
            self._make_mandate(),
            status_list_credential="https://gauth.example/status/1",
            status_list_index=42,
        )
        assert vc["credentialStatus"]["type"] == "BitstringStatusListEntry"
        assert vc["credentialStatus"]["statusListIndex"] == 42


class TestVCJWTPayload:
    """CT-CF-006–007 — VC → JWT payload."""

    def test_ct_cf_006_jwt_payload_has_standard_claims(self):
        vc = poa_to_vc({
            "mandate_id": "m1",
            "parties": {"subject": "agent-1", "project_id": "p1"},
            "scope": {"core_verbs": {}, "governance_profile": "minimal", "phase": "build"},
            "requirements": {},
            "budget_state": {},
            "activated_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-12-31T23:59:59+00:00",
        })
        payload = vc_to_jwt_payload(vc)
        assert "iss" in payload
        assert "sub" in payload
        assert "jti" in payload
        assert "iat" in payload
        assert "vc" in payload
        assert "nbf" in payload
        assert "exp" in payload

    def test_ct_cf_007_jwt_payload_embeds_vc(self):
        vc = poa_to_vc({
            "mandate_id": "m1",
            "parties": {"subject": "agent-1", "project_id": "p1"},
            "scope": {"core_verbs": {}, "governance_profile": "minimal", "phase": "build"},
            "requirements": {},
            "budget_state": {},
        })
        payload = vc_to_jwt_payload(vc)
        assert payload["vc"]["@context"] == vc["@context"]
        assert payload["vc"]["type"] == vc["type"]


class TestDIDResolution:
    """CT-CF-008–010 — DID resolution (did:web, did:key)."""

    def test_ct_cf_008_resolve_did_web(self):
        doc = resolve_did_web("did:web:gauth.gimel.foundation:proj1")
        assert doc["id"] == "did:web:gauth.gimel.foundation:proj1"
        assert len(doc["verificationMethod"]) > 0
        assert doc["_resolution"]["resolved"] is True

    def test_ct_cf_009_resolve_did_key(self):
        doc = resolve_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        assert doc["id"] == "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        assert doc["_resolution"]["resolved"] is True

    def test_ct_cf_009b_create_did_key(self):
        result = create_did_key("abcdef1234567890")
        assert result["did"].startswith("did:key:z")
        assert "did_document" in result

    def test_ct_cf_010_resolve_did_dispatch(self):
        web = resolve_did("did:web:example.com")
        assert web["id"] == "did:web:example.com"

        key = resolve_did("did:key:z123")
        assert key["id"] == "did:key:z123"

        unsupported = resolve_did("did:ion:abc")
        assert "error" in unsupported


class TestDataIntegrityProofs:
    """CT-CF-011–012 — Data Integrity Proofs."""

    def test_ct_cf_011_create_proof(self):
        vc = poa_to_vc({
            "mandate_id": "m1",
            "parties": {"subject": "a1", "project_id": "p1"},
            "scope": {"core_verbs": {}, "governance_profile": "minimal", "phase": "build"},
            "requirements": {},
            "budget_state": {},
        })
        proof = create_data_integrity_proof(vc, verification_method="did:key:z123#key-1")
        assert proof["type"] == "DataIntegrityProof"
        assert proof["cryptosuite"] == "ecdsa-rdfc-2019"
        assert proof["proofPurpose"] == "assertionMethod"
        assert len(proof["proofValue"]) > 0

    def test_ct_cf_012_verify_proof_roundtrip(self):
        vc = poa_to_vc({
            "mandate_id": "m1",
            "parties": {"subject": "a1", "project_id": "p1"},
            "scope": {"core_verbs": {}, "governance_profile": "minimal", "phase": "build"},
            "requirements": {},
            "budget_state": {},
        })
        proof = create_data_integrity_proof(vc)
        vc_with_proof = {**vc, "proof": proof}
        result = verify_data_integrity_proof(vc_with_proof)
        assert result["verified"] is True

    def test_ct_cf_012b_verify_proof_detects_tampering(self):
        vc = poa_to_vc({
            "mandate_id": "m1",
            "parties": {"subject": "a1", "project_id": "p1"},
            "scope": {"core_verbs": {}, "governance_profile": "minimal", "phase": "build"},
            "requirements": {},
            "budget_state": {},
        })
        proof = create_data_integrity_proof(vc)
        vc_tampered = {**vc, "proof": proof}
        vc_tampered["credentialSubject"]["mandate_id"] = "TAMPERED"
        result = verify_data_integrity_proof(vc_tampered)
        assert result["verified"] is False

    def test_ct_cf_012c_verify_no_proof_returns_false(self):
        result = verify_data_integrity_proof({"id": "test"})
        assert result["verified"] is False


class TestSDJWT:
    """CT-CF-013–015 — SD-JWT selective disclosure."""

    def test_ct_cf_013_create_sd_jwt(self):
        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m1",
                "budget_total_cents": 5000,
                "scope_checksum": "abc",
            },
        }
        result = create_sd_jwt(vc_payload, redacted_claims=["budget_total_cents"])
        assert "compact" in result
        assert len(result["disclosures"]) >= 1
        assert "~" in result["compact"]

    def test_ct_cf_014_verify_sd_jwt_reveals_claims(self):
        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m1",
                "budget_total_cents": 5000,
                "scope_checksum": "abc123",
            },
        }
        sd = create_sd_jwt(vc_payload, redacted_claims=["budget_total_cents", "scope_checksum"])
        verification = verify_sd_jwt_disclosures(sd["compact"])
        assert verification["valid"] is True
        assert verification["disclosure_count"] == 2
        assert "budget_total_cents" in verification["revealed_claims"]
        assert verification["revealed_claims"]["budget_total_cents"] == 5000

    def test_ct_cf_015_sd_jwt_no_redaction_no_disclosures(self):
        vc_payload = {
            "credentialSubject": {"mandate_id": "m1"},
        }
        result = create_sd_jwt(vc_payload, redacted_claims=[])
        assert len(result["disclosures"]) == 0


class TestBitstringStatusList:
    """CT-CF-016–017 — Bitstring Status List v2.0."""

    def test_ct_cf_016_set_and_check_revocation(self):
        sl = BitstringStatusList(size=1024)
        assert sl.get_status(42) is False
        sl.set_status(42, True, reason="test revocation")
        assert sl.get_status(42) is True
        assert sl.get_revocation_reason(42) == "test revocation"

    def test_ct_cf_016b_encode_decode_roundtrip(self):
        sl = BitstringStatusList(size=1024)
        sl.set_status(0, True)
        sl.set_status(100, True)
        sl.set_status(500, True)

        encoded = sl.encode()
        decoded = BitstringStatusList.decode(encoded, size=1024)
        assert decoded.get_status(0) is True
        assert decoded.get_status(100) is True
        assert decoded.get_status(500) is True
        assert decoded.get_status(1) is False

    def test_ct_cf_017_status_list_credential(self):
        sl = BitstringStatusList(size=1024)
        sl.set_status(10, True)
        cred = sl.to_status_list_credential(
            credential_id="https://gauth.example/status/1",
            issuer_did="did:web:gauth.example",
        )
        assert "BitstringStatusListCredential" in cred["type"]
        assert cred["credentialSubject"]["statusPurpose"] == "revocation"
        assert cred["credentialSubject"]["encodedList"] == sl.encode()

    def test_ct_cf_017b_check_revocation_method(self):
        sl = BitstringStatusList(size=1024)
        sl.set_status(5, True, reason="compromised")
        result = sl.check_revocation({
            "statusListIndex": 5,
            "statusListCredential": "https://gauth.example/status/1",
        })
        assert result["revoked"] is True
        assert result["reason"] == "compromised"

    def test_ct_cf_017c_out_of_range_raises(self):
        sl = BitstringStatusList(size=256)
        with pytest.raises(ValueError):
            sl.set_status(256, True)
        with pytest.raises(ValueError):
            sl.get_status(-1)


class TestOpenID4VCI:
    """CT-CF-018 — OpenID4VCI stub."""

    def test_ct_cf_018_credential_offer(self):
        stub = OpenID4VCIStub()
        offer = stub.create_credential_offer()
        assert "credential_issuer" in offer
        assert "credential_configuration_ids" in offer
        assert "GAuthPoACredential" in offer["credential_configuration_ids"]

    def test_ct_cf_018b_issuer_metadata(self):
        stub = OpenID4VCIStub()
        meta = stub.get_issuer_metadata()
        assert "GAuthPoACredential" in meta["credential_configurations_supported"]

    def test_ct_cf_018c_token_and_credential_endpoints(self):
        stub = OpenID4VCIStub()
        tok = stub.token_endpoint("code_123")
        assert "access_token" in tok
        cred = stub.credential_endpoint(tok["access_token"])
        assert "credential" in cred


class TestOpenID4VP:
    """CT-CF-019 — OpenID4VP stub."""

    def test_ct_cf_019_presentation_request(self):
        stub = OpenID4VPStub()
        req = stub.create_presentation_request()
        assert "presentation_definition" in req
        assert "nonce" in req
        assert "session_id" in req

    def test_ct_cf_019b_submit_and_verify(self):
        stub = OpenID4VPStub()
        req = stub.create_presentation_request()
        session_id = req["session_id"]
        result = stub.submit_presentation(session_id, vp_token="token.payload.sig")
        assert result["verified"] is True

    def test_ct_cf_019c_session_status(self):
        stub = OpenID4VPStub()
        req = stub.create_presentation_request()
        session_id = req["session_id"]
        status = stub.get_session_status(session_id)
        assert status["status"] == "pending"

        stub.submit_presentation(session_id, vp_token="tok")
        status = stub.get_session_status(session_id)
        assert status["status"] == "verified"

    def test_ct_cf_019d_unknown_session(self):
        stub = OpenID4VPStub()
        result = stub.submit_presentation("nonexistent", vp_token="tok")
        assert result["verified"] is False


class TestVCModuleImports:
    """CT-CF supplemental — vc module __init__.py exports."""

    def test_vc_module_exports(self):
        from gauth_core.vc import (
            poa_to_vc,
            vc_to_jwt_payload,
            resolve_did_web,
            resolve_did_key,
            create_did_key,
            BitstringStatusList,
            create_sd_jwt,
            verify_sd_jwt_disclosures,
            OpenID4VCIStub,
            OpenID4VPStub,
        )
        assert callable(poa_to_vc)
        assert callable(resolve_did_web)
        assert callable(create_sd_jwt)


class TestVCSchemaTypes:
    """CT-CF supplemental — schema/vc.py Pydantic models."""

    def test_verifiable_credential_model(self):
        from gauth_core.schema.vc import VerifiableCredential
        vc = VerifiableCredential()
        assert "VerifiableCredential" in vc.type
        assert "GAuthPoACredential" in vc.type

    def test_did_document_model(self):
        from gauth_core.schema.vc import DIDDocument
        doc = DIDDocument(id="did:web:example.com")
        assert doc.id == "did:web:example.com"

    def test_sd_frame_model(self):
        from gauth_core.schema.vc import SDFrame
        frame = SDFrame(disclosed_claims=["a", "b"], redacted_claims=["c"])
        assert len(frame.disclosed_claims) == 2


class TestCTCFSecurityHardening:
    """CT-CF-020–027: Security hardening for SD-JWT and VC schema aliases."""

    def test_sd_jwt_redacts_claims_from_payload(self):
        """CT-CF-020: Redacted claims MUST NOT appear in issuer payload."""
        from gauth_core.vc.sd_jwt import create_sd_jwt, _base64url_decode
        import json

        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m-123",
                "governance_profile": "strict",
                "secret_field": "sensitive-value",
            }
        }
        result = create_sd_jwt(vc_payload, redacted_claims=["secret_field"])

        jwt_parts = result["compact"].split("~")[0].split(".")
        payload_json = _base64url_decode(jwt_parts[1]).decode()
        payload = json.loads(payload_json)

        subject = payload.get("credentialSubject", {})
        assert "secret_field" not in subject
        assert "mandate_id" in subject
        assert "governance_profile" in subject

    def test_sd_jwt_verify_fails_on_tampered_disclosure(self):
        """CT-CF-021: Tampered disclosures MUST yield valid=False."""
        from gauth_core.vc.sd_jwt import create_sd_jwt, verify_sd_jwt_disclosures

        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m-123",
                "secret_field": "sensitive",
            }
        }
        result = create_sd_jwt(vc_payload, redacted_claims=["secret_field"])

        parts = result["compact"].split("~")
        jwt_part = parts[0]
        tampered = jwt_part + "~INVALID_DISCLOSURE_DATA~"
        verification = verify_sd_jwt_disclosures(tampered)
        assert verification["valid"] is False

    def test_sd_jwt_verify_fails_on_empty_jwt(self):
        """CT-CF-022: Empty JWT part MUST yield valid=False."""
        from gauth_core.vc.sd_jwt import verify_sd_jwt_disclosures
        result = verify_sd_jwt_disclosures("")
        assert result["valid"] is False

    def test_sd_jwt_verify_valid_disclosures_pass(self):
        """CT-CF-023: Valid disclosures from create_sd_jwt MUST verify."""
        from gauth_core.vc.sd_jwt import create_sd_jwt, verify_sd_jwt_disclosures

        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m-456",
                "secret_field": "hidden",
            }
        }
        result = create_sd_jwt(vc_payload, redacted_claims=["secret_field"])
        verification = verify_sd_jwt_disclosures(result["compact"])
        assert verification["valid"] is True
        assert "secret_field" in verification["revealed_claims"]

    def test_vc_schema_proof_aliases_roundtrip(self):
        """CT-CF-024: DataIntegrityProof camelCase aliases must roundtrip."""
        from gauth_core.schema.vc import DataIntegrityProof

        proof_data = {
            "verificationMethod": "did:web:example.com#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndTh...",
        }
        proof = DataIntegrityProof(**proof_data)
        assert proof.verification_method == "did:web:example.com#key-1"
        assert proof.proof_value == "z58DAdFfa9SkqZMVPxAQpic7ndTh..."

        dumped = proof.model_dump(by_alias=True)
        assert dumped["verificationMethod"] == "did:web:example.com#key-1"
        assert dumped["proofPurpose"] == "assertionMethod"
        assert dumped["proofValue"] == "z58DAdFfa9SkqZMVPxAQpic7ndTh..."

    def test_vc_schema_status_aliases_roundtrip(self):
        """CT-CF-025: BitstringStatusListEntry camelCase aliases must roundtrip."""
        from gauth_core.schema.vc import BitstringStatusListEntry

        entry_data = {
            "statusPurpose": "revocation",
            "statusListIndex": 42,
            "statusListCredential": "https://example.com/status/1",
        }
        entry = BitstringStatusListEntry(**entry_data)
        assert entry.status_list_index == 42
        assert entry.status_list_credential == "https://example.com/status/1"

        dumped = entry.model_dump(by_alias=True)
        assert dumped["statusListIndex"] == 42
        assert dumped["statusListCredential"] == "https://example.com/status/1"
        assert dumped["statusPurpose"] == "revocation"

    def test_vc_serializer_output_parses_into_schema(self):
        """CT-CF-026: Serializer output must parse into VC schema models."""
        from gauth_core.vc.serializer import poa_to_vc
        from gauth_core.schema.vc import VerifiableCredential

        mandate = {
            "mandate_id": "test-roundtrip",
            "status": "active",
            "scope": {
                "governance_profile": "standard",
                "phase": "exploration",
                "allowed_actions": ["read"],
                "allowed_sectors": ["health"],
                "allowed_regions": ["EU"],
                "allowed_decisions": ["informational"],
                "core_verbs": {"read": True},
            },
            "parties": {
                "issued_by": "did:web:issuer.example",
                "issued_to": "agent-1",
                "subject": "agent-1",
            },
            "requirements": {"approval_mode": "supervised"},
        }
        vc_dict = poa_to_vc(mandate)
        vc = VerifiableCredential.model_validate(vc_dict)
        assert vc.credential_subject.mandate_id == "test-roundtrip"
        assert vc.credential_subject.governance_profile == "standard"

    def test_sd_jwt_no_redaction_keeps_all_claims(self):
        """CT-CF-027: No redaction preserves all claims in payload."""
        from gauth_core.vc.sd_jwt import create_sd_jwt, _base64url_decode
        import json

        vc_payload = {
            "credentialSubject": {
                "mandate_id": "m-789",
                "governance_profile": "minimal",
            }
        }
        result = create_sd_jwt(vc_payload, redacted_claims=[])
        jwt_parts = result["compact"].split("~")[0].split(".")
        payload_json = _base64url_decode(jwt_parts[1]).decode()
        payload = json.loads(payload_json)
        subject = payload.get("credentialSubject", {})
        assert subject["mandate_id"] == "m-789"
        assert subject["governance_profile"] == "minimal"
        assert "_sd" not in payload
