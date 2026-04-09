"""GAuth PoA credential types — RFC 0116 §4.3 schema models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ToolPolicy(BaseModel):
    allowed: bool = True
    requires_approval: bool = False
    max_per_session: int | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)


class PlatformPermissions(BaseModel):
    deployment_targets: list[str] = Field(default_factory=list)
    auto_deploy: bool = False
    db_write: bool = False
    db_migration: bool = False
    db_production: bool = False
    shell_mode: str = "any"
    packages_audited_only: bool = False
    secrets_read: bool = False
    secrets_create: bool = False


class DelegationEntry(BaseModel):
    delegator: str
    delegate: str
    scope_restriction: dict[str, Any] = Field(default_factory=dict)
    delegated_at: datetime
    max_depth_remaining: int = 0


class SessionLimits(BaseModel):
    max_tool_calls: int | None = None
    max_session_duration_minutes: int | None = None
    max_lines_per_commit: int | None = None


class Budget(BaseModel):
    total_cents: int = Field(ge=0)


class BudgetDetail(BaseModel):
    total_cents: int = Field(ge=0)
    remaining_cents: int = Field(ge=0)
    consumed_cents: int = Field(ge=0)
    utilization_percent: float = Field(ge=0.0, le=100.0)
    reserved_for_delegations_cents: int = Field(ge=0, default=0)


class MandateScope(BaseModel):
    governance_profile: str
    phase: str
    core_verbs: dict[str, ToolPolicy] = Field(default_factory=dict)
    platform_permissions: PlatformPermissions = Field(default_factory=PlatformPermissions)
    active_modules: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    allowed_sectors: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)
    allowed_transactions: list[str] = Field(default_factory=list)
    transaction_matrix: dict[str, Any] = Field(default_factory=dict)
    allowed_decisions: list[str] = Field(default_factory=list)


class MandateRequirements(BaseModel):
    approval_mode: str
    budget: Budget
    ttl_seconds: int = Field(ge=60)
    session_limits: SessionLimits = Field(default_factory=SessionLimits)
