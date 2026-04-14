"""GAuth governance profile ceiling table — RFC 0118 §9.2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gauth_core.schema.enums import ApprovalMode, GovernanceProfile, ShellMode, APPROVAL_MODE_RANK


@dataclass(frozen=True)
class CeilingDefinition:
    deployment_targets: frozenset[str]
    auto_deploy: bool
    db_write: bool
    db_migration: bool
    db_production: bool
    shell_mode: ShellMode
    packages_audited_only: bool
    secrets_read: bool
    secrets_create: bool
    agent_delegation: bool
    max_delegation_depth: int
    min_approval_mode: ApprovalMode
    max_session_duration_minutes: int | None
    max_tool_calls: int | None
    max_lines_per_commit: int | None
    approval_required_for_delegation: bool = False
    description: str = ""
    registration_context: str = ""


CEILING_TABLE: dict[GovernanceProfile, CeilingDefinition] = {
    GovernanceProfile.MINIMAL: CeilingDefinition(
        deployment_targets=frozenset({"dev", "staging", "prod"}),
        auto_deploy=True,
        db_write=True,
        db_migration=True,
        db_production=True,
        shell_mode=ShellMode.ANY,
        packages_audited_only=False,
        secrets_read=True,
        secrets_create=True,
        agent_delegation=True,
        max_delegation_depth=99,
        min_approval_mode=ApprovalMode.AUTONOMOUS,
        max_session_duration_minutes=None,
        max_tool_calls=None,
        max_lines_per_commit=None,
        description="Least restrictive. Maximum autonomy.",
        registration_context="Prototyping, personal projects",
    ),
    GovernanceProfile.STANDARD: CeilingDefinition(
        deployment_targets=frozenset({"dev", "staging"}),
        auto_deploy=False,
        db_write=True,
        db_migration=False,
        db_production=False,
        shell_mode=ShellMode.DENYLIST,
        packages_audited_only=False,
        secrets_read=True,
        secrets_create=False,
        agent_delegation=True,
        max_delegation_depth=1,
        min_approval_mode=ApprovalMode.SUPERVISED,
        max_session_duration_minutes=240,
        max_tool_calls=500,
        max_lines_per_commit=500,
        approval_required_for_delegation=True,
        description="Balanced restrictions. Supervised approval.",
        registration_context="Small teams, general development",
    ),
    GovernanceProfile.STRICT: CeilingDefinition(
        deployment_targets=frozenset({"staging"}),
        auto_deploy=False,
        db_write=True,
        db_migration=False,
        db_production=False,
        shell_mode=ShellMode.ALLOWLIST,
        packages_audited_only=True,
        secrets_read=True,
        secrets_create=False,
        agent_delegation=True,
        max_delegation_depth=1,
        min_approval_mode=ApprovalMode.SUPERVISED,
        max_session_duration_minutes=120,
        max_tool_calls=200,
        max_lines_per_commit=200,
        approval_required_for_delegation=True,
        description="Restrictive. Audited packages, allowlist shell.",
        registration_context="Regulated industries",
    ),
    GovernanceProfile.ENTERPRISE: CeilingDefinition(
        deployment_targets=frozenset({"staging"}),
        auto_deploy=False,
        db_write=False,
        db_migration=False,
        db_production=False,
        shell_mode=ShellMode.ALLOWLIST,
        packages_audited_only=True,
        secrets_read=False,
        secrets_create=False,
        agent_delegation=False,
        max_delegation_depth=0,
        min_approval_mode=ApprovalMode.SUPERVISED,
        max_session_duration_minutes=60,
        max_tool_calls=100,
        max_lines_per_commit=100,
        description="Highly restrictive. No delegation, no secrets access.",
        registration_context="Enterprise organizations",
    ),
    GovernanceProfile.BEHOERDE: CeilingDefinition(
        deployment_targets=frozenset({"staging"}),
        auto_deploy=False,
        db_write=False,
        db_migration=False,
        db_production=False,
        shell_mode=ShellMode.ALLOWLIST,
        packages_audited_only=True,
        secrets_read=False,
        secrets_create=False,
        agent_delegation=False,
        max_delegation_depth=0,
        min_approval_mode=ApprovalMode.FOUR_EYES,
        max_session_duration_minutes=30,
        max_tool_calls=100,
        max_lines_per_commit=100,
        description="Most restrictive. Four-eyes approval, 30-minute sessions.",
        registration_context="Public sector / government",
    ),
}


def get_ceiling(profile: GovernanceProfile | str) -> CeilingDefinition:
    if isinstance(profile, str):
        profile = GovernanceProfile(profile)
    ceiling = CEILING_TABLE.get(profile)
    if ceiling is None:
        raise ValueError(f"Unknown governance profile: {profile}")
    return ceiling


def get_profile_info(profile: GovernanceProfile | str) -> dict[str, Any]:
    ceiling = get_ceiling(profile)
    p = GovernanceProfile(profile) if isinstance(profile, str) else profile
    return {
        "name": p.value,
        "description": ceiling.description,
        "registration_context": ceiling.registration_context,
    }


def list_profiles() -> list[dict[str, Any]]:
    return [get_profile_info(p) for p in GovernanceProfile]


def validate_against_ceiling(
    profile: GovernanceProfile | str,
    scope: dict[str, Any],
    requirements: dict[str, Any],
) -> list[dict[str, Any]]:
    ceiling = get_ceiling(profile)
    violations: list[dict[str, Any]] = []

    platform = scope.get("platform_permissions", {})

    if platform.get("auto_deploy", False) and not ceiling.auto_deploy:
        violations.append({
            "attribute": "auto_deploy",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("db_write", False) and not ceiling.db_write:
        violations.append({
            "attribute": "db_write",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("db_migration", False) and not ceiling.db_migration:
        violations.append({
            "attribute": "db_migration",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("db_production", False) and not ceiling.db_production:
        violations.append({
            "attribute": "db_production",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("secrets_read", False) and not ceiling.secrets_read:
        violations.append({
            "attribute": "secrets_read",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("secrets_create", False) and not ceiling.secrets_create:
        violations.append({
            "attribute": "secrets_create",
            "requested": True,
            "ceiling": False,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    if platform.get("packages_audited_only") is False and ceiling.packages_audited_only:
        violations.append({
            "attribute": "packages_audited_only",
            "requested": False,
            "ceiling": True,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    req_targets = set(platform.get("deployment_targets", []))
    if req_targets and not req_targets.issubset(ceiling.deployment_targets):
        violations.append({
            "attribute": "deployment_targets",
            "requested": sorted(req_targets),
            "ceiling": sorted(ceiling.deployment_targets),
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    shell = platform.get("shell_mode", "any")
    shell_rank = {"any": 0, "denylist": 1, "allowlist": 2}
    if shell_rank.get(shell, 0) < shell_rank.get(ceiling.shell_mode.value, 0):
        violations.append({
            "attribute": "shell_mode",
            "requested": shell,
            "ceiling": ceiling.shell_mode.value,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    approval = requirements.get("approval_mode", "autonomous")
    req_rank = APPROVAL_MODE_RANK.get(ApprovalMode(approval), 0)
    ceil_rank = APPROVAL_MODE_RANK.get(ceiling.min_approval_mode, 0)
    if req_rank < ceil_rank:
        violations.append({
            "attribute": "min_approval_mode",
            "requested": approval,
            "ceiling": ceiling.min_approval_mode.value,
            "profile": ceiling.description,
            "code": "CEILING_VIOLATION",
        })

    session = requirements.get("session_limits", {})

    if ceiling.max_session_duration_minutes is not None:
        req_dur = session.get("max_session_duration_minutes")
        if req_dur is not None and req_dur > ceiling.max_session_duration_minutes:
            violations.append({
                "attribute": "max_session_duration_minutes",
                "requested": req_dur,
                "ceiling": ceiling.max_session_duration_minutes,
                "profile": ceiling.description,
                "code": "CEILING_VIOLATION",
            })

    if ceiling.max_tool_calls is not None:
        req_tc = session.get("max_tool_calls")
        if req_tc is not None and req_tc > ceiling.max_tool_calls:
            violations.append({
                "attribute": "max_tool_calls",
                "requested": req_tc,
                "ceiling": ceiling.max_tool_calls,
                "profile": ceiling.description,
                "code": "CEILING_VIOLATION",
            })

    if ceiling.max_lines_per_commit is not None:
        req_lpc = session.get("max_lines_per_commit")
        if req_lpc is not None and req_lpc > ceiling.max_lines_per_commit:
            violations.append({
                "attribute": "max_lines_per_commit",
                "requested": req_lpc,
                "ceiling": ceiling.max_lines_per_commit,
                "profile": ceiling.description,
                "code": "CEILING_VIOLATION",
            })

    if not ceiling.agent_delegation:
        core_verbs = scope.get("core_verbs", {})
        for verb_name, verb_policy in core_verbs.items():
            if isinstance(verb_policy, dict) and verb_policy.get("constraints", {}).get("max_delegation_depth", 0) > 0:
                violations.append({
                    "attribute": "agent_delegation",
                    "requested": True,
                    "ceiling": False,
                    "profile": ceiling.description,
                    "code": "CEILING_VIOLATION",
                })
                break

    return violations
