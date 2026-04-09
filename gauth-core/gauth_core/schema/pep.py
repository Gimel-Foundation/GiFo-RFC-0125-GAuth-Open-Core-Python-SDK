"""GAuth PEP types — RFC 0117 enforcement request/decision models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from gauth_core.schema.enums import CheckSeverity, Decision, EnforcementMode


class ActionDescriptor(BaseModel):
    verb: str
    resource: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class EnforcementContext(BaseModel):
    agent_id: str
    session_id: str | None = None
    timestamp: datetime
    enforcement_mode: EnforcementMode | None = None
    ip_address: str | None = None
    user_agent: str | None = None


class PoASnapshot(BaseModel):
    mandate_id: str
    subject: str
    issuer: str = ""
    governance_profile: str
    phase: str
    core_verbs: dict[str, Any] = Field(default_factory=dict)
    platform_permissions: dict[str, Any] = Field(default_factory=dict)
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    allowed_sectors: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)
    allowed_transactions: list[str] = Field(default_factory=list)
    transaction_matrix: dict[str, Any] = Field(default_factory=dict)
    allowed_decisions: list[str] = Field(default_factory=list)
    active_modules: list[str] = Field(default_factory=list)
    approval_mode: str = "autonomous"
    budget_total_cents: int = 0
    budget_remaining_cents: int = 0
    ttl_seconds: int = 0
    session_limits: dict[str, Any] = Field(default_factory=dict)
    delegation_chain: list[dict[str, Any]] = Field(default_factory=list)
    scope_checksum: str = ""
    tool_permissions_hash: str = ""
    platform_permissions_hash: str = ""
    exp: datetime | None = None
    nbf: datetime | None = None
    aud: str | None = None
    jti: str | None = None
    status: str = "ACTIVE"


class EnforcementRequest(BaseModel):
    request_id: str
    credential: PoASnapshot
    action: ActionDescriptor
    context: EnforcementContext


class CheckResult(BaseModel):
    check_id: str
    check_name: str
    result: str
    severity: CheckSeverity = CheckSeverity.INFO
    violation_code: str | None = None
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class EnforcedConstraint(BaseModel):
    constraint_type: str
    source_check: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    message: str = ""


class EnforcementAudit(BaseModel):
    request_id: str
    credential_ref: str
    enforcement_mode: EnforcementMode
    processing_time_ms: float
    pep_interface_version: str = "1.1"
    timestamp: datetime
    checks_evaluated: int = 0


class EnforcementDecision(BaseModel):
    request_id: str
    decision: Decision
    checks: list[CheckResult] = Field(default_factory=list)
    enforced_constraints: list[EnforcedConstraint] = Field(default_factory=list)
    violations: list[CheckResult] = Field(default_factory=list)
    audit: EnforcementAudit
    effective_scope: dict[str, Any] | None = None


class EnforcementError(BaseModel):
    request_id: str
    error_code: str
    message: str
    timestamp: datetime
