"""MandateManagementService — all lifecycle operations per RFC 0118."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from gauth_core.schema.enums import (
    TERMINAL_STATUSES,
    ManagementErrorCode,
    MandateStatus,
    OperationType,
)
from gauth_core.profiles.ceilings import get_ceiling, list_profiles, GovernanceProfile, CEILING_TABLE
from gauth_core.storage.base import MandateRepository
from gauth_core.utils.checksums import (
    compute_platform_permissions_hash,
    compute_scope_checksum,
    compute_tool_permissions_hash,
)
from gauth_core.validation.pipeline import validate_mandate, ValidationResult


class ManagementError(Exception):
    def __init__(self, code: ManagementErrorCode, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class MandateManagementService:

    def __init__(self, repository: MandateRepository) -> None:
        self._repo = repository

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _generate_id(self) -> str:
        return f"mdt_{uuid.uuid4().hex[:12]}"

    def _audit(self, operation: OperationType, performed_by: str, mandate_id: str, **extra: Any) -> dict[str, Any]:
        record = {
            "operation": operation.value,
            "performed_by": performed_by,
            "timestamp": self._now().isoformat(),
            "mandate_id": mandate_id,
            **extra,
        }
        self._repo.store_audit_record(record)
        return record

    def create_mandate(self, data: dict[str, Any]) -> dict[str, Any]:
        validation = validate_mandate(data)
        if not validation.accepted:
            raise ManagementError(
                ManagementErrorCode.SCHEMA_VALIDATION_FAILED,
                "Mandate validation failed",
                {"validation": validation.to_dict()},
            )

        mandate_id = self._generate_id()
        now = self._now()
        scope = data["scope"]
        scope_checksum = compute_scope_checksum(scope)
        tool_hash = compute_tool_permissions_hash(scope.get("core_verbs", {}))
        platform_hash = compute_platform_permissions_hash(scope.get("platform_permissions", {}))

        total_cents = data["requirements"]["budget"]["total_cents"]
        mandate = {
            "mandate_id": mandate_id,
            "status": MandateStatus.DRAFT.value,
            "parties": data["parties"],
            "scope": scope,
            "requirements": data["requirements"],
            "scope_checksum": scope_checksum,
            "tool_permissions_hash": tool_hash,
            "platform_permissions_hash": platform_hash,
            "created_at": now.isoformat(),
            "activated_at": None,
            "expires_at": None,
            "ttl_seconds": data["requirements"]["ttl_seconds"],
            "budget_state": {
                "total_cents": total_cents,
                "remaining_cents": total_cents,
                "consumed_cents": 0,
                "reserved_for_delegations_cents": 0,
            },
        }

        self._repo.create(mandate)
        audit = self._audit(OperationType.CREATE, data["parties"]["issued_by"], mandate_id)

        return {
            "mandate_id": mandate_id,
            "status": MandateStatus.DRAFT.value,
            "scope_checksum": scope_checksum,
            "tool_permissions_hash": tool_hash,
            "platform_permissions_hash": platform_hash,
            "created_at": now.isoformat(),
            "validation": validation.to_dict(),
            "audit": audit,
        }

    def activate_mandate(self, mandate_id: str, activated_by: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] != MandateStatus.DRAFT.value:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_DRAFT, "Mandate must be in DRAFT state to activate")

        validation = validate_mandate({
            "parties": mandate["parties"],
            "scope": mandate["scope"],
            "requirements": mandate["requirements"],
        })
        if not validation.accepted:
            raise ManagementError(
                ManagementErrorCode.SCHEMA_VALIDATION_FAILED,
                "Re-validation failed at activation time",
                {"validation": validation.to_dict()},
            )

        agent_id = mandate["parties"]["subject"]
        project_id = mandate["parties"]["project_id"]
        existing = self._repo.find_active_mandate(agent_id, project_id)
        superseded_id = None
        if existing and existing["mandate_id"] != mandate_id:
            self._repo.update_status(existing["mandate_id"], MandateStatus.SUPERSEDED.value)
            self._audit(OperationType.SUPERSEDE, activated_by, existing["mandate_id"])
            superseded_id = existing["mandate_id"]

        now = self._now()
        ttl = mandate["ttl_seconds"]
        expires_at = now + timedelta(seconds=ttl)

        self._repo.update_status(
            mandate_id,
            MandateStatus.ACTIVE.value,
            activated_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
        )

        audit = self._audit(OperationType.ACTIVATE, activated_by, mandate_id)

        return {
            "mandate_id": mandate_id,
            "status": MandateStatus.ACTIVE.value,
            "activated_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "superseded_mandate_id": superseded_id,
            "audit": audit,
        }

    def revoke_mandate(self, mandate_id: str, revoked_by: str, reason: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] in {s.value for s in TERMINAL_STATUSES}:
            raise ManagementError(
                ManagementErrorCode.INVALID_STATE_TRANSITION,
                f"Cannot revoke mandate in {mandate['status']} state",
            )

        if mandate["status"] not in {MandateStatus.ACTIVE.value, MandateStatus.SUSPENDED.value}:
            raise ManagementError(
                ManagementErrorCode.MANDATE_NOT_ACTIVE,
                "Mandate must be ACTIVE or SUSPENDED to revoke",
            )

        now = self._now()
        self._repo.update_status(mandate_id, MandateStatus.REVOKED.value, revoked_at=now.isoformat())

        cascaded = self._cascade_status(mandate_id, MandateStatus.REVOKED, revoked_by, "PARENT_REVOKED")

        audit = self._audit(OperationType.REVOKE, revoked_by, mandate_id, reason=reason)

        return {
            "mandate_id": mandate_id,
            "status": MandateStatus.REVOKED.value,
            "revoked_at": now.isoformat(),
            "revoked_by": revoked_by,
            "reason": reason,
            "cascaded_revocations": cascaded,
            "audit": audit,
        }

    def suspend_mandate(self, mandate_id: str, suspended_by: str, reason: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] != MandateStatus.ACTIVE.value:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_ACTIVE, "Mandate must be ACTIVE to suspend")

        now = self._now()
        self._repo.update_status(mandate_id, MandateStatus.SUSPENDED.value, suspended_at=now.isoformat())

        cascaded = self._cascade_status(mandate_id, MandateStatus.SUSPENDED, suspended_by, "PARENT_SUSPENDED")

        audit = self._audit(OperationType.SUSPEND, suspended_by, mandate_id, reason=reason)

        return {
            "mandate_id": mandate_id,
            "status": MandateStatus.SUSPENDED.value,
            "suspended_at": now.isoformat(),
            "suspended_by": suspended_by,
            "reason": reason,
            "cascaded_suspensions": cascaded,
            "audit": audit,
        }

    def resume_mandate(self, mandate_id: str, resumed_by: str, reason: str = "") -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] != MandateStatus.SUSPENDED.value:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_SUSPENDED, "Mandate must be SUSPENDED to resume")

        expires_at = mandate.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= self._now():
                self._repo.update_status(mandate_id, MandateStatus.EXPIRED.value)
                raise ManagementError(ManagementErrorCode.MANDATE_EXPIRED, "Mandate expired during suspension")

        now = self._now()
        self._repo.update_status(mandate_id, MandateStatus.ACTIVE.value, resumed_at=now.isoformat())

        remaining_ttl = 0
        if expires_at:
            exp = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            remaining_ttl = max(0, int((exp - now).total_seconds()))

        self._cascade_resume(mandate_id, resumed_by)

        audit = self._audit(OperationType.RESUME, resumed_by, mandate_id, reason=reason)

        return {
            "mandate_id": mandate_id,
            "status": MandateStatus.ACTIVE.value,
            "resumed_at": now.isoformat(),
            "resumed_by": resumed_by,
            "remaining_ttl_seconds": remaining_ttl,
            "audit": audit,
        }

    def increase_budget(self, mandate_id: str, additional_cents: int, increased_by: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] not in {MandateStatus.ACTIVE.value, MandateStatus.SUSPENDED.value}:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_ACTIVE, "Mandate must be ACTIVE or SUSPENDED")

        if additional_cents <= 0:
            raise ManagementError(ManagementErrorCode.BUDGET_DECREASE_NOT_ALLOWED, "Budget can only increase")

        budget = mandate.get("budget_state", {})
        prev_total = budget.get("total_cents", 0)
        prev_remaining = budget.get("remaining_cents", 0)
        new_total = prev_total + additional_cents
        new_remaining = prev_remaining + additional_cents

        self._repo.update_budget(mandate_id, new_total, new_remaining)
        audit = self._audit(OperationType.BUDGET_INCREASE, increased_by, mandate_id)

        return {
            "mandate_id": mandate_id,
            "previous_total_cents": prev_total,
            "new_total_cents": new_total,
            "remaining_cents": new_remaining,
            "audit": audit,
        }

    def consume_budget(
        self,
        mandate_id: str,
        enforcement_request_id: str,
        consumed_cents: int,
        action_verb: str,
        resource: str,
    ) -> dict[str, Any]:
        if self._repo.check_consumption_idempotency(enforcement_request_id):
            mandate = self._repo.get(mandate_id)
            budget = mandate.get("budget_state", {}) if mandate else {}
            return {
                "mandate_id": mandate_id,
                "enforcement_request_id": enforcement_request_id,
                "accepted": True,
                "remaining_cents": budget.get("remaining_cents", 0),
                "budget_exceeded": False,
                "audit": {"operation": "BUDGET_CONSUME", "note": "duplicate_idempotent"},
            }

        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] != MandateStatus.ACTIVE.value:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_ACTIVE, "Mandate must be ACTIVE")

        if consumed_cents <= 0:
            raise ManagementError(
                ManagementErrorCode.BUDGET_DECREASE_NOT_ALLOWED,
                "consumed_cents must be > 0",
            )

        budget = mandate.get("budget_state", {})
        remaining = budget.get("remaining_cents", 0)
        new_remaining = max(0, remaining - consumed_cents)
        new_total = budget.get("total_cents", 0)

        self._repo.record_consumption(mandate_id, enforcement_request_id, consumed_cents)
        self._repo.update_budget(mandate_id, new_total, new_remaining)

        budget_exceeded = new_remaining == 0
        if budget_exceeded:
            self._repo.update_status(mandate_id, MandateStatus.BUDGET_EXCEEDED.value)

        audit = self._audit(OperationType.BUDGET_CONSUME, "pep_system", mandate_id)

        return {
            "mandate_id": mandate_id,
            "enforcement_request_id": enforcement_request_id,
            "accepted": True,
            "remaining_cents": new_remaining,
            "budget_exceeded": budget_exceeded,
            "audit": audit,
        }

    def extend_ttl(self, mandate_id: str, additional_seconds: int, extended_by: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        if mandate["status"] not in {MandateStatus.ACTIVE.value, MandateStatus.SUSPENDED.value}:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_ACTIVE, "Mandate must be ACTIVE or SUSPENDED")

        if additional_seconds <= 0:
            raise ManagementError(ManagementErrorCode.TTL_DECREASE_NOT_ALLOWED, "TTL can only increase")

        prev_ttl = mandate.get("ttl_seconds", 0)
        new_ttl = prev_ttl + additional_seconds

        expires_at = mandate.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at) if isinstance(expires_at, str) else expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            new_expires = exp + timedelta(seconds=additional_seconds)
        else:
            new_expires = self._now() + timedelta(seconds=new_ttl)

        self._repo.update_ttl(mandate_id, new_ttl, new_expires.isoformat())
        audit = self._audit(OperationType.TTL_EXTEND, extended_by, mandate_id)

        return {
            "mandate_id": mandate_id,
            "previous_ttl_seconds": prev_ttl,
            "new_ttl_seconds": new_ttl,
            "new_expires_at": new_expires.isoformat(),
            "audit": audit,
        }

    def get_mandate(self, mandate_id: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")
        return mandate

    def list_mandates(self, **filters: Any) -> dict[str, Any]:
        mandates, next_cursor, total = self._repo.list_mandates(**filters)
        return {
            "mandates": mandates,
            "next_cursor": next_cursor,
            "total_count": total,
        }

    def get_history(self, mandate_id: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")
        history = self._repo.get_audit_trail(mandate_id)
        return {"mandate_id": mandate_id, "history": history}

    def get_budget_state(self, mandate_id: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")
        budget = mandate.get("budget_state", {})
        total = budget.get("total_cents", 0)
        remaining = budget.get("remaining_cents", 0)
        consumed = budget.get("consumed_cents", 0)
        reserved = budget.get("reserved_for_delegations_cents", 0)
        return {
            "mandate_id": mandate_id,
            "total_cents": total,
            "remaining_cents": remaining,
            "consumed_cents": consumed,
            "reserved_for_delegations_cents": reserved,
            "utilization_percent": round((consumed / total * 100) if total > 0 else 0.0, 1),
            "budget_exceeded": remaining == 0 and total > 0,
        }

    def delete_draft(self, mandate_id: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")
        if mandate["status"] != MandateStatus.DRAFT.value:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_DRAFT, "Only DRAFT mandates can be deleted")
        self._repo.update_status(mandate_id, "DELETED")
        return {"mandate_id": mandate_id, "deleted": True}

    def create_delegation(
        self,
        parent_mandate_id: str,
        delegate_agent_id: str,
        scope_restriction: dict[str, Any],
        budget_cents: int,
        ttl_seconds: int,
        delegated_by: str,
    ) -> dict[str, Any]:
        parent = self._repo.get(parent_mandate_id)
        if not parent:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Parent {parent_mandate_id} not found")

        if parent["status"] != MandateStatus.ACTIVE.value:
            raise ManagementError(ManagementErrorCode.PARENT_MANDATE_NOT_ACTIVE, "Parent must be ACTIVE")

        profile_name = parent["scope"].get("governance_profile", "minimal")
        try:
            ceiling = get_ceiling(profile_name)
        except ValueError:
            raise ManagementError(ManagementErrorCode.PROFILE_NOT_FOUND, f"Unknown profile: {profile_name}")

        if not ceiling.agent_delegation:
            raise ManagementError(ManagementErrorCode.DELEGATION_DEPTH_EXCEEDED, "Profile does not allow delegation")

        chain = self._repo.get_delegation_chain(parent_mandate_id)
        current_depth = len(chain)
        if current_depth >= ceiling.max_delegation_depth:
            raise ManagementError(
                ManagementErrorCode.DELEGATION_DEPTH_EXCEEDED,
                f"Delegation depth {current_depth + 1} exceeds max {ceiling.max_delegation_depth}",
            )

        parent_budget = parent.get("budget_state", {})
        available = parent_budget.get("remaining_cents", 0) - parent_budget.get("reserved_for_delegations_cents", 0)
        if budget_cents > available:
            raise ManagementError(
                ManagementErrorCode.DELEGATION_BUDGET_EXCEEDED,
                f"Requested {budget_cents} cents exceeds available {available} cents",
            )

        parent_ttl = parent.get("ttl_seconds", 0)
        if parent.get("expires_at"):
            exp = datetime.fromisoformat(parent["expires_at"]) if isinstance(parent["expires_at"], str) else parent["expires_at"]
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            remaining_parent_ttl = max(0, int((exp - self._now()).total_seconds()))
        else:
            remaining_parent_ttl = parent_ttl

        if ttl_seconds > remaining_parent_ttl:
            raise ManagementError(
                ManagementErrorCode.DELEGATION_TTL_EXCEEDED,
                f"Requested TTL {ttl_seconds}s exceeds parent remaining {remaining_parent_ttl}s",
            )

        child_id = self._generate_id()
        now = self._now()
        expires_at = now + timedelta(seconds=ttl_seconds)

        child_scope = {**parent["scope"]}
        if scope_restriction:
            list_keys = {"allowed_paths", "allowed_sectors", "allowed_regions",
                         "allowed_transactions", "allowed_decisions"}
            additive_keys = {"denied_paths"}
            bool_restrict_keys = {"platform_permissions"}
            for key, value in scope_restriction.items():
                if key not in child_scope:
                    continue
                if key in list_keys:
                    parent_set = set(child_scope.get(key, []))
                    child_set = set(value) if isinstance(value, list) else {value}
                    if parent_set:
                        child_scope[key] = sorted(parent_set & child_set)
                    else:
                        child_scope[key] = sorted(child_set)
                elif key in additive_keys:
                    child_scope[key] = sorted(
                        set(child_scope.get(key, [])) | set(value if isinstance(value, list) else [value])
                    )
                elif key == "core_verbs":
                    parent_verbs = child_scope.get("core_verbs", {})
                    restricted_verbs = value if isinstance(value, dict) else {}
                    narrowed = {}
                    for k, v in parent_verbs.items():
                        if k in restricted_verbs:
                            narrowed[k] = restricted_verbs[k]
                    child_scope["core_verbs"] = narrowed
                elif key in bool_restrict_keys and isinstance(value, dict):
                    parent_dict = child_scope.get(key, {})
                    if isinstance(parent_dict, dict):
                        narrowed_dict = {}
                        for dk, dv in parent_dict.items():
                            if dk in value:
                                if isinstance(dv, bool) and isinstance(value[dk], bool):
                                    narrowed_dict[dk] = dv and value[dk]
                                elif isinstance(dv, list) and isinstance(value[dk], list):
                                    narrowed_dict[dk] = sorted(set(dv) & set(value[dk]))
                                else:
                                    narrowed_dict[dk] = dv
                            else:
                                narrowed_dict[dk] = dv
                        child_scope[key] = narrowed_dict
                elif key in {"governance_profile", "phase"}:
                    child_scope[key] = value

        child_mandate = {
            "mandate_id": child_id,
            "status": MandateStatus.ACTIVE.value,
            "parties": {
                "subject": delegate_agent_id,
                "customer_id": parent["parties"]["customer_id"],
                "project_id": parent["parties"]["project_id"],
                "issued_by": delegated_by,
            },
            "scope": child_scope,
            "requirements": {
                **parent["requirements"],
                "budget": {"total_cents": budget_cents},
                "ttl_seconds": ttl_seconds,
            },
            "scope_checksum": compute_scope_checksum(child_scope),
            "tool_permissions_hash": compute_tool_permissions_hash(child_scope.get("core_verbs", {})),
            "platform_permissions_hash": compute_platform_permissions_hash(
                child_scope.get("platform_permissions", {})
            ),
            "created_at": now.isoformat(),
            "activated_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ttl_seconds": ttl_seconds,
            "budget_state": {
                "total_cents": budget_cents,
                "remaining_cents": budget_cents,
                "consumed_cents": 0,
                "reserved_for_delegations_cents": 0,
            },
            "parent_mandate_id": parent_mandate_id,
        }

        self._repo.create(child_mandate)
        self._repo.store_delegation(parent_mandate_id, child_id, {
            "delegate_agent_id": delegate_agent_id,
            "scope_restriction": scope_restriction,
            "budget_cents": budget_cents,
            "ttl_seconds": ttl_seconds,
            "delegated_by": delegated_by,
            "delegated_at": now.isoformat(),
            "depth": current_depth + 1,
        })

        new_reserved = parent_budget.get("reserved_for_delegations_cents", 0) + budget_cents
        parent_remaining = parent_budget.get("remaining_cents", 0)
        self._repo.update_budget(
            parent_mandate_id,
            parent_budget.get("total_cents", 0),
            parent_remaining,
        )
        self._repo.update_reservation(parent_mandate_id, new_reserved)

        audit = self._audit(
            OperationType.DELEGATE, delegated_by, child_id,
            parent_mandate_id=parent_mandate_id,
        )

        return {
            "mandate_id": child_id,
            "parent_mandate_id": parent_mandate_id,
            "status": MandateStatus.ACTIVE.value,
            "delegate_agent_id": delegate_agent_id,
            "scope_restriction": scope_restriction,
            "budget_cents": budget_cents,
            "ttl_seconds": ttl_seconds,
            "delegation_depth": current_depth + 1,
            "parent_budget_after_deduction": {
                "total_cents": parent_budget.get("total_cents", 0),
                "remaining_cents": parent_remaining,
                "consumed_cents": parent_budget.get("consumed_cents", 0),
                "reserved_for_delegations_cents": new_reserved,
            },
            "audit": audit,
        }

    def get_delegation_chain(self, mandate_id: str) -> dict[str, Any]:
        mandate = self._repo.get(mandate_id)
        if not mandate:
            raise ManagementError(ManagementErrorCode.MANDATE_NOT_FOUND, f"Mandate {mandate_id} not found")

        chain_raw = self._repo.get_delegation_chain(mandate_id)
        chain = []
        for i, entry in enumerate(chain_raw):
            parent = self._repo.get(entry.get("parent_mandate_id", ""))
            chain.append({
                "level": i,
                "mandate_id": entry.get("parent_mandate_id", ""),
                "agent_id": parent["parties"]["subject"] if parent else "",
                "role": "root" if i == 0 else "delegate",
                "status": parent["status"] if parent else "UNKNOWN",
            })

        chain.append({
            "level": len(chain),
            "mandate_id": mandate_id,
            "agent_id": mandate["parties"]["subject"],
            "role": "delegate" if chain else "root",
            "status": mandate["status"],
        })

        profile_name = mandate["scope"].get("governance_profile", "minimal")
        try:
            ceiling = get_ceiling(profile_name)
            max_depth = ceiling.max_delegation_depth
        except ValueError:
            max_depth = 0

        return {
            "mandate_id": mandate_id,
            "chain": chain,
            "effective_scope": mandate["scope"],
            "max_depth": max_depth,
            "remaining_depth": max(0, max_depth - len(chain_raw)),
        }

    def get_profiles(self) -> list[dict[str, Any]]:
        return list_profiles()

    def get_profile_ceilings(self, profile_name: str) -> dict[str, Any]:
        try:
            ceiling = get_ceiling(profile_name)
        except ValueError:
            raise ManagementError(ManagementErrorCode.PROFILE_NOT_FOUND, f"Unknown profile: {profile_name}")

        return {
            "profile": profile_name,
            "ceilings": {
                "deployment_targets": sorted(ceiling.deployment_targets),
                "auto_deploy": ceiling.auto_deploy,
                "db_write": ceiling.db_write,
                "db_migration": ceiling.db_migration,
                "db_production": ceiling.db_production,
                "shell_mode": ceiling.shell_mode.value,
                "packages_audited_only": ceiling.packages_audited_only,
                "secrets_read": ceiling.secrets_read,
                "secrets_create": ceiling.secrets_create,
                "agent_delegation": ceiling.agent_delegation,
                "max_delegation_depth": ceiling.max_delegation_depth,
                "min_approval_mode": ceiling.min_approval_mode.value,
                "max_session_duration_minutes": ceiling.max_session_duration_minutes,
                "max_tool_calls": ceiling.max_tool_calls,
                "max_lines_per_commit": ceiling.max_lines_per_commit,
            },
        }

    def _cascade_status(
        self, parent_id: str, target_status: MandateStatus, performed_by: str, reason: str,
    ) -> list[str]:
        children = self._repo.get_children(parent_id)
        cascaded: list[str] = []
        for child in children:
            child_id = child["mandate_id"]
            if child["status"] in {s.value for s in TERMINAL_STATUSES}:
                continue
            self._repo.update_status(child_id, target_status.value)
            self._audit(
                OperationType.REVOKE if target_status == MandateStatus.REVOKED else OperationType.SUSPEND,
                performed_by,
                child_id,
                reason=reason,
            )
            cascaded.append(child_id)
            cascaded.extend(self._cascade_status(child_id, target_status, performed_by, reason))
        return cascaded

    def _cascade_resume(self, parent_id: str, resumed_by: str) -> None:
        children = self._repo.get_children(parent_id)
        for child in children:
            if child["status"] == MandateStatus.SUSPENDED.value:
                self._repo.update_status(child["mandate_id"], MandateStatus.ACTIVE.value)
                self._audit(OperationType.RESUME, resumed_by, child["mandate_id"], reason="PARENT_RESUMED")
                self._cascade_resume(child["mandate_id"], resumed_by)
