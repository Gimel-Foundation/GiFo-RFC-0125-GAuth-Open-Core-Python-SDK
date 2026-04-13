"""GAuth Management API types — RFC 0118 request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from gauth_core.schema.enums import ManagementErrorCode, MandateStatus, OperationType
from gauth_core.schema.poa import BudgetDetail, DelegationEntry, MandateRequirements, MandateScope, SessionLimits


class MandateParties(BaseModel):
    subject: str
    customer_id: str
    project_id: str
    issued_by: str
    approval_chain: list[str] = Field(default_factory=list)


class AuditRecord(BaseModel):
    operation: OperationType
    performed_by: str
    timestamp: datetime
    mandate_id: str
    parent_mandate_id: str | None = None
    reason: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ValidationDetail(BaseModel):
    accepted: bool
    schema_errors: list[dict[str, Any]] = Field(default_factory=list)
    ceiling_violations: list[dict[str, Any]] = Field(default_factory=list)
    consistency_errors: list[dict[str, Any]] = Field(default_factory=list)


class MandateCreationRequest(BaseModel):
    parties: MandateParties
    scope: MandateScope
    requirements: MandateRequirements


class MandateCreationResponse(BaseModel):
    mandate_id: str
    status: MandateStatus = MandateStatus.DRAFT
    scope_checksum: str
    tool_permissions_hash: str
    platform_permissions_hash: str
    created_at: datetime
    validation: ValidationDetail
    audit: AuditRecord


class MandateActivationRequest(BaseModel):
    mandate_id: str
    activated_by: str


class MandateActivationResponse(BaseModel):
    mandate_id: str
    status: MandateStatus = MandateStatus.ACTIVE
    activated_at: datetime
    expires_at: datetime
    superseded_mandate_id: str | None = None
    audit: AuditRecord


class MandateRevocationRequest(BaseModel):
    mandate_id: str
    revoked_by: str
    reason: str


class MandateRevocationResponse(BaseModel):
    mandate_id: str
    status: MandateStatus = MandateStatus.REVOKED
    revoked_at: datetime
    revoked_by: str
    reason: str
    cascaded_revocations: list[str] = Field(default_factory=list)
    audit: AuditRecord


class MandateSuspensionRequest(BaseModel):
    mandate_id: str
    suspended_by: str
    reason: str


class MandateSuspensionResponse(BaseModel):
    mandate_id: str
    status: MandateStatus = MandateStatus.SUSPENDED
    suspended_at: datetime
    suspended_by: str
    reason: str
    cascaded_suspensions: list[str] = Field(default_factory=list)
    audit: AuditRecord


class MandateResumptionRequest(BaseModel):
    mandate_id: str
    resumed_by: str
    reason: str = ""


class MandateResumptionResponse(BaseModel):
    mandate_id: str
    status: MandateStatus = MandateStatus.ACTIVE
    resumed_at: datetime
    resumed_by: str
    remaining_ttl_seconds: int
    audit: AuditRecord


class BudgetIncreaseRequest(BaseModel):
    mandate_id: str
    additional_cents: int = Field(gt=0)
    increased_by: str


class BudgetIncreaseResponse(BaseModel):
    mandate_id: str
    previous_total_cents: int
    new_total_cents: int
    remaining_cents: int
    audit: AuditRecord


class ConsumptionReport(BaseModel):
    mandate_id: str
    enforcement_request_id: str
    consumed_cents: int = Field(gt=0)
    action_verb: str
    resource: str
    reported_at: datetime


class ConsumptionAcknowledgement(BaseModel):
    mandate_id: str
    enforcement_request_id: str
    accepted: bool
    remaining_cents: int
    budget_exceeded: bool = False
    audit: AuditRecord


class TTLExtensionRequest(BaseModel):
    mandate_id: str
    additional_seconds: int = Field(gt=0)
    extended_by: str


class TTLExtensionResponse(BaseModel):
    mandate_id: str
    previous_ttl_seconds: int
    new_ttl_seconds: int
    new_expires_at: datetime
    audit: AuditRecord


class DelegationRequest(BaseModel):
    parent_mandate_id: str
    delegate_agent_id: str
    scope_restriction: dict[str, Any] = Field(default_factory=dict)
    budget_cents: int = Field(ge=0)
    ttl_seconds: int = Field(ge=60)
    delegated_by: str


class DelegationResponse(BaseModel):
    mandate_id: str
    parent_mandate_id: str
    status: MandateStatus = MandateStatus.ACTIVE
    delegate_agent_id: str
    scope_restriction: dict[str, Any]
    budget_cents: int
    ttl_seconds: int
    delegation_depth: int
    parent_budget_after_deduction: BudgetDetail
    audit: AuditRecord


class RequirementsDetail(BaseModel):
    approval_mode: str
    budget: BudgetDetail
    session_limits: SessionLimits = Field(default_factory=SessionLimits)
    ttl_seconds: int
    remaining_ttl_seconds: int


class PartiesDetail(BaseModel):
    issuer: str = ""
    subject: str
    customer_id: str
    project_id: str
    issued_by: str


class MandateDetail(BaseModel):
    mandate_id: str
    status: MandateStatus
    parties: PartiesDetail
    scope: MandateScope
    requirements: RequirementsDetail
    scope_checksum: str
    tool_permissions_hash: str
    platform_permissions_hash: str
    created_at: datetime
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    delegation_chain: list[DelegationEntry] = Field(default_factory=list)


class MandateListQuery(BaseModel):
    status: MandateStatus | None = None
    agent_id: str | None = None
    project_id: str | None = None
    governance_profile: str | None = None
    cursor: str | None = None
    limit: int = Field(default=20, ge=1, le=100)


class MandateListItem(BaseModel):
    mandate_id: str
    status: MandateStatus
    subject: str
    project_id: str
    governance_profile: str
    budget_utilization_percent: float
    remaining_ttl_seconds: int | None
    created_at: datetime


class MandateListResponse(BaseModel):
    mandates: list[MandateListItem]
    next_cursor: str | None = None
    total_count: int


class MandateHistoryResponse(BaseModel):
    mandate_id: str
    history: list[AuditRecord]


class BudgetState(BaseModel):
    mandate_id: str
    total_cents: int
    remaining_cents: int
    consumed_cents: int
    reserved_for_delegations_cents: int
    utilization_percent: float
    budget_exceeded: bool


class DelegationChainEntry(BaseModel):
    level: int
    mandate_id: str
    agent_id: str
    role: str
    status: MandateStatus
    delegated_by: str | None = None
    delegated_at: datetime | None = None


class DelegationChainResponse(BaseModel):
    mandate_id: str
    chain: list[DelegationChainEntry]
    effective_scope: dict[str, Any] = Field(default_factory=dict)
    max_depth: int
    remaining_depth: int


class ProfileInfo(BaseModel):
    name: str
    description: str
    registration_context: str


class CeilingTable(BaseModel):
    profile: str
    ceilings: dict[str, Any]


class ManagementError(BaseModel):
    error_code: ManagementErrorCode
    message: str
    timestamp: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None
    retry_after_seconds: int | None = None


class PoaPermissionEntry(BaseModel):
    action: str
    resource: str | None = None
    effect: str


class PoaMapSummary(BaseModel):
    mandate_id: str
    subject: str
    governance_profile: str
    status: MandateStatus
    permissions: list[PoaPermissionEntry] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_decisions: list[str] = Field(default_factory=list)

    @property
    def allowedActions(self) -> list[str]:
        return self.allowed_actions

    @property
    def allowedDecisions(self) -> list[str]:
        return self.allowed_decisions


class HealthResponse(BaseModel):
    status: str = "ok"
    mgmt_version: str = "1.1.0"
    interface_version: str = "1.1"
    supported_schema_version: str = "0116.2.2"
    features: dict[str, bool] = Field(default_factory=lambda: {
        "suspension": True,
        "ttl_extension": True,
        "budget_consumption_reporting": True,
    })
