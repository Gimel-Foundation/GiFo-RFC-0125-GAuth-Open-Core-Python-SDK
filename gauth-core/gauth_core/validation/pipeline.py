"""Three-stage validation pipeline — RFC 0118 §10."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from gauth_core.schema.enums import ApprovalMode, GovernanceProfile
from gauth_core.schema.mgmt import MandateCreationRequest
from gauth_core.profiles.ceilings import validate_against_ceiling, get_ceiling


@dataclass
class ValidationResult:
    accepted: bool = True
    schema_errors: list[dict[str, Any]] = field(default_factory=list)
    ceiling_violations: list[dict[str, Any]] = field(default_factory=list)
    consistency_errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "schema_errors": self.schema_errors,
            "ceiling_violations": self.ceiling_violations,
            "consistency_errors": self.consistency_errors,
        }


def validate_schema(data: dict[str, Any]) -> tuple[MandateCreationRequest | None, list[dict[str, Any]]]:
    try:
        request = MandateCreationRequest.model_validate(data)
        return request, []
    except ValidationError as e:
        errors = []
        for err in e.errors():
            errors.append({
                "path": ".".join(str(p) for p in err["loc"]),
                "error": err["msg"],
                "code": "SCHEMA_TYPE_MISMATCH",
            })
        return None, errors


def validate_ceilings(scope: dict[str, Any], requirements: dict[str, Any]) -> list[dict[str, Any]]:
    profile_name = scope.get("governance_profile", "")
    try:
        GovernanceProfile(profile_name)
    except ValueError:
        return [{
            "attribute": "governance_profile",
            "requested": profile_name,
            "ceiling": "N/A",
            "profile": "N/A",
            "code": "PROFILE_NOT_FOUND",
        }]

    return validate_against_ceiling(profile_name, scope, requirements)


def validate_consistency(
    scope: dict[str, Any],
    requirements: dict[str, Any],
    parties: dict[str, Any],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []

    approval_mode = requirements.get("approval_mode", "autonomous")
    approval_chain = parties.get("approval_chain", [])
    if approval_mode == "four-eyes":
        unique_approvers = set(approval_chain)
        if len(unique_approvers) < 2:
            errors.append({
                "rule": "C-1",
                "message": "four-eyes approval mode requires approval_chain with >= 2 distinct entries",
                "code": "FOUR_EYES_MISSING_APPROVERS",
            })

    allowed_paths = set(scope.get("allowed_paths", []))
    denied_paths = set(scope.get("denied_paths", []))
    path_conflicts = allowed_paths & denied_paths
    if path_conflicts:
        errors.append({
            "rule": "C-2",
            "message": f"denied_paths and allowed_paths contain the same entries: {sorted(path_conflicts)}",
            "code": "PATH_CONFLICT",
        })

    budget = requirements.get("budget", {})
    total_cents = budget.get("total_cents", 0)
    if total_cents < 0:
        errors.append({
            "rule": "C-3",
            "message": "Budget total_cents must be >= 0",
            "code": "INVALID_BUDGET",
        })

    ttl_seconds = requirements.get("ttl_seconds", 0)
    if ttl_seconds < 60:
        errors.append({
            "rule": "C-4",
            "message": "TTL must be >= 60 seconds",
            "code": "TTL_TOO_SHORT",
        })

    core_verbs = scope.get("core_verbs", {})
    if core_verbs:
        for verb, policy in core_verbs.items():
            if isinstance(policy, dict):
                if not policy.get("allowed", True) and policy.get("requires_approval", False):
                    errors.append({
                        "rule": "C-5",
                        "message": f"Verb '{verb}' is disallowed but also requires approval — contradictory",
                        "code": "VERB_POLICY_CONTRADICTION",
                    })

    platform_perms = scope.get("platform_permissions", {})
    governance_profile = scope.get("governance_profile", "")
    if governance_profile and platform_perms:
        try:
            profile_enum = GovernanceProfile(governance_profile)
            ceiling = get_ceiling(profile_enum)
            if platform_perms.get("db_production", False) and not ceiling.db_production:
                errors.append({
                    "rule": "C-6",
                    "message": f"db_production access requested but profile '{governance_profile}' forbids it",
                    "code": "PLATFORM_PROFILE_MISMATCH",
                })
            if platform_perms.get("db_migration", False) and not ceiling.db_migration:
                errors.append({
                    "rule": "C-6",
                    "message": f"db_migration access requested but profile '{governance_profile}' forbids it",
                    "code": "PLATFORM_PROFILE_MISMATCH",
                })
        except ValueError:
            pass

    return errors


def validate_mandate(data: dict[str, Any]) -> ValidationResult:
    result = ValidationResult()

    parsed, schema_errors = validate_schema(data)
    if schema_errors:
        result.schema_errors = schema_errors
        result.accepted = False

    scope_data = data.get("scope", {})
    req_data = data.get("requirements", {})
    parties_data = data.get("parties", {})

    ceiling_violations = validate_ceilings(scope_data, req_data)
    if ceiling_violations:
        result.ceiling_violations = ceiling_violations
        result.accepted = False

    consistency_errors = validate_consistency(scope_data, req_data, parties_data)
    if consistency_errors:
        result.consistency_errors = consistency_errors
        result.accepted = False

    return result
