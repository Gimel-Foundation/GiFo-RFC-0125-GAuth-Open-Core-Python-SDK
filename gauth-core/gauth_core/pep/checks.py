"""Individual PEP check implementations — CHK-01 through CHK-16."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone
from typing import Any

from gauth_core.schema.enums import (
    ApprovalMode,
    CheckSeverity,
    EnforcementMode,
    GovernanceProfile,
    MandateStatus,
    APPROVAL_MODE_RANK,
)
from gauth_core.profiles.ceilings import get_ceiling


def _check_result(
    check_id: str,
    check_name: str,
    passed: bool,
    severity: CheckSeverity = CheckSeverity.ERROR,
    violation_code: str | None = None,
    message: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "check_name": check_name,
        "result": "pass" if passed else "fail",
        "severity": severity.value,
        "violation_code": violation_code,
        "message": message,
        "details": details or {},
    }


def chk_01_credential(credential: dict[str, Any], **_: Any) -> dict[str, Any]:
    required = ["mandate_id", "subject", "governance_profile", "phase"]
    missing = [f for f in required if not credential.get(f)]
    if missing:
        return _check_result(
            "CHK-01", "Credential Validation", False,
            CheckSeverity.ERROR, "CREDENTIAL_INVALID",
            f"Missing required fields: {missing}",
        )
    checksum = credential.get("scope_checksum", "")
    if not checksum:
        return _check_result(
            "CHK-01", "Credential Validation", False,
            CheckSeverity.WARNING, "CREDENTIAL_CHECKSUM_MISSING",
            "scope_checksum is empty",
        )
    return _check_result("CHK-01", "Credential Validation", True, message="Credential structure valid")


def chk_02_temporal(
    credential: dict[str, Any],
    context: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)

    exp = credential.get("exp")
    if exp:
        exp_dt = exp if isinstance(exp, datetime) else datetime.fromisoformat(str(exp))
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if now > exp_dt:
            return _check_result(
                "CHK-02", "Temporal Validity", False,
                CheckSeverity.ERROR, "CREDENTIAL_EXPIRED",
                "Credential has expired",
            )

    nbf = credential.get("nbf")
    if nbf:
        nbf_dt = nbf if isinstance(nbf, datetime) else datetime.fromisoformat(str(nbf))
        if nbf_dt.tzinfo is None:
            nbf_dt = nbf_dt.replace(tzinfo=timezone.utc)
        if now < nbf_dt:
            return _check_result(
                "CHK-02", "Temporal Validity", False,
                CheckSeverity.ERROR, "CREDENTIAL_NOT_YET_VALID",
                "Credential not yet valid",
            )

    if mode == EnforcementMode.STATEFUL and live_mandate:
        status = live_mandate.get("status", "")
        if status != MandateStatus.ACTIVE.value:
            return _check_result(
                "CHK-02", "Temporal Validity", False,
                CheckSeverity.ERROR, "MANDATE_NOT_ACTIVE",
                f"Live mandate status is {status}",
            )

    agent_id = context.get("agent_id", "")
    subject = credential.get("subject", "")
    if agent_id and subject and agent_id != subject:
        return _check_result(
            "CHK-02", "Temporal Validity", False,
            CheckSeverity.ERROR, "AGENT_MISMATCH",
            f"Agent {agent_id} does not match credential subject {subject}",
        )

    return _check_result("CHK-02", "Temporal Validity", True, message="Temporal checks passed")


def chk_03_profile(credential: dict[str, Any], **_: Any) -> dict[str, Any]:
    profile_name = credential.get("governance_profile", "")
    try:
        GovernanceProfile(profile_name)
    except ValueError:
        return _check_result(
            "CHK-03", "Governance Profile", False,
            CheckSeverity.ERROR, "UNKNOWN_GOVERNANCE_PROFILE",
            f"Unknown governance profile: {profile_name}",
        )

    ceiling = get_ceiling(profile_name)
    session = credential.get("session_limits", {})
    dur = session.get("max_session_duration_minutes")
    if dur and ceiling.max_session_duration_minutes and dur > ceiling.max_session_duration_minutes:
        return _check_result(
            "CHK-03", "Governance Profile", False,
            CheckSeverity.ERROR, "PROFILE_CEILING_EXCEEDED",
            f"Session duration {dur} exceeds ceiling {ceiling.max_session_duration_minutes}",
        )

    return _check_result("CHK-03", "Governance Profile", True, message="Profile check passed")


def chk_04_phase(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    phase = credential.get("phase", "")
    if not phase:
        return _check_result(
            "CHK-04", "Phase", False, CheckSeverity.ERROR,
            "PHASE_MISSING", "No phase in credential",
        )
    return _check_result("CHK-04", "Phase", True, message=f"Phase '{phase}' valid")


def chk_05_sector(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    sectors = credential.get("allowed_sectors", [])
    if not sectors:
        return _check_result("CHK-05", "Sector", True, message="No sector restrictions")
    req_sector = action.get("parameters", {}).get("sector")
    if req_sector and req_sector not in sectors:
        return _check_result(
            "CHK-05", "Sector", False, CheckSeverity.ERROR,
            "SECTOR_NOT_ALLOWED", f"Sector '{req_sector}' not in allowed sectors",
        )
    return _check_result("CHK-05", "Sector", True, message="Sector check passed")


def chk_06_region(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    regions = credential.get("allowed_regions", [])
    if not regions:
        return _check_result("CHK-06", "Region", True, message="No region restrictions")
    req_region = action.get("parameters", {}).get("region")
    if req_region and req_region not in regions:
        return _check_result(
            "CHK-06", "Region", False, CheckSeverity.ERROR,
            "REGION_NOT_ALLOWED", f"Region '{req_region}' not in allowed regions",
        )
    return _check_result("CHK-06", "Region", True, message="Region check passed")


def chk_07_path(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    resource = action.get("resource", "")
    denied = credential.get("denied_paths", [])
    for pattern in denied:
        if fnmatch.fnmatch(resource, pattern) or resource.startswith(pattern):
            return _check_result(
                "CHK-07", "Path", False, CheckSeverity.ERROR,
                "PATH_DENIED", f"Resource '{resource}' matches denied path '{pattern}'",
            )

    allowed = credential.get("allowed_paths", [])
    if allowed:
        matched = any(
            fnmatch.fnmatch(resource, p) or resource.startswith(p)
            for p in allowed
        )
        if not matched:
            return _check_result(
                "CHK-07", "Path", False, CheckSeverity.ERROR,
                "PATH_NOT_ALLOWED", f"Resource '{resource}' not in allowed paths",
            )

    return _check_result("CHK-07", "Path", True, message="Path check passed")


def chk_08_verb(
    credential: dict[str, Any],
    action: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    verb = action.get("verb", "")

    if mode == EnforcementMode.STATEFUL and live_mandate:
        core_verbs = live_mandate.get("scope", {}).get("core_verbs", {})
    else:
        core_verbs = credential.get("core_verbs", {})

    if not core_verbs:
        return _check_result("CHK-08", "Verb", True, message="No verb restrictions (empty core_verbs)")

    parts = verb.split(".")
    matched_policy = None
    for i in range(len(parts), 0, -1):
        candidate = ".".join(parts[:i])
        if candidate in core_verbs:
            matched_policy = core_verbs[candidate]
            break

    if matched_policy is None:
        if "*" in core_verbs:
            matched_policy = core_verbs["*"]
        else:
            return _check_result(
                "CHK-08", "Verb", False, CheckSeverity.ERROR,
                "VERB_NOT_AUTHORIZED", f"Verb '{verb}' not in core_verbs",
            )

    if isinstance(matched_policy, dict):
        if not matched_policy.get("allowed", True):
            return _check_result(
                "CHK-08", "Verb", False, CheckSeverity.ERROR,
                "VERB_NOT_ALLOWED", f"Verb '{verb}' is explicitly disallowed",
            )

    return _check_result("CHK-08", "Verb", True, message=f"Verb '{verb}' authorized")


def chk_09_constraints(
    credential: dict[str, Any],
    action: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    if mode == EnforcementMode.STATELESS:
        return _check_result(
            "CHK-09", "Constraints", True,
            CheckSeverity.INFO, message="Constraints check skipped in stateless mode",
        )

    if live_mandate:
        core_verbs = live_mandate.get("scope", {}).get("core_verbs", {})
    else:
        core_verbs = credential.get("core_verbs", {})

    verb = action.get("verb", "")
    policy = core_verbs.get(verb, {})
    if isinstance(policy, dict) and policy.get("constraints"):
        return _check_result(
            "CHK-09", "Constraints", True,
            CheckSeverity.INFO, message="Constraints present",
            details={"constraints": policy["constraints"]},
        )

    return _check_result("CHK-09", "Constraints", True, message="No constraints to evaluate")


def chk_10_platform(
    credential: dict[str, Any],
    action: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    if mode == EnforcementMode.STATELESS:
        return _check_result(
            "CHK-10", "Platform Permissions", True,
            CheckSeverity.INFO, message="Platform check (hash-only in stateless mode)",
        )

    if live_mandate:
        platform = live_mandate.get("scope", {}).get("platform_permissions", {})
    else:
        platform = credential.get("platform_permissions", {})

    verb = action.get("verb", "")
    if "deploy" in verb.lower() and not platform.get("auto_deploy", False):
        deploy_targets = platform.get("deployment_targets", [])
        target = action.get("parameters", {}).get("target", "")
        if target and target not in deploy_targets:
            return _check_result(
                "CHK-10", "Platform Permissions", False,
                CheckSeverity.ERROR, "PLATFORM_PERMISSION_DENIED",
                f"Deployment target '{target}' not allowed",
            )

    if "db" in verb.lower() and "write" in verb.lower():
        if not platform.get("db_write", False):
            return _check_result(
                "CHK-10", "Platform Permissions", False,
                CheckSeverity.ERROR, "PLATFORM_PERMISSION_DENIED",
                "Database write access not permitted",
            )

    return _check_result("CHK-10", "Platform Permissions", True, message="Platform permissions check passed")


def chk_11_transaction(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    allowed_tx = credential.get("allowed_transactions", [])
    if not allowed_tx:
        return _check_result("CHK-11", "Transaction", True, message="No transaction restrictions")

    tx_type = action.get("parameters", {}).get("transaction_type")
    if tx_type and tx_type not in allowed_tx:
        return _check_result(
            "CHK-11", "Transaction", False, CheckSeverity.ERROR,
            "TRANSACTION_NOT_ALLOWED", f"Transaction type '{tx_type}' not allowed",
        )

    return _check_result("CHK-11", "Transaction", True, message="Transaction check passed")


def chk_12_decision(credential: dict[str, Any], action: dict[str, Any], **_: Any) -> dict[str, Any]:
    allowed_decisions = credential.get("allowed_decisions", [])
    if not allowed_decisions:
        return _check_result("CHK-12", "Decision Type", True, message="No decision type restrictions")

    decision_type = action.get("parameters", {}).get("decision_type")
    if decision_type and decision_type not in allowed_decisions:
        return _check_result(
            "CHK-12", "Decision Type", False, CheckSeverity.ERROR,
            "DECISION_TYPE_NOT_ALLOWED", f"Decision type '{decision_type}' not allowed",
        )

    return _check_result("CHK-12", "Decision Type", True, message="Decision type check passed")


def chk_13_budget(
    credential: dict[str, Any],
    action: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    if mode == EnforcementMode.STATEFUL and live_mandate:
        budget = live_mandate.get("budget_state", {})
        remaining = budget.get("remaining_cents", 0)
    else:
        remaining = credential.get("budget_remaining_cents", 0)

    cost = action.get("parameters", {}).get("estimated_cost_cents", 0)
    if cost > 0 and remaining < cost:
        return _check_result(
            "CHK-13", "Budget", False, CheckSeverity.ERROR,
            "BUDGET_EXCEEDED", f"Estimated cost {cost} exceeds remaining budget {remaining}",
        )

    if remaining <= 0 and credential.get("budget_total_cents", 0) > 0:
        return _check_result(
            "CHK-13", "Budget", False, CheckSeverity.ERROR,
            "BUDGET_EXHAUSTED", "Budget fully consumed",
        )

    return _check_result("CHK-13", "Budget", True, message="Budget check passed")


def chk_14_session(credential: dict[str, Any], context: dict[str, Any], **_: Any) -> dict[str, Any]:
    session_limits = credential.get("session_limits", {})
    if not session_limits:
        return _check_result("CHK-14", "Session Limits", True, message="No session limits")

    max_calls = session_limits.get("max_tool_calls")
    current_calls = context.get("session_tool_calls", 0)
    if max_calls and current_calls >= max_calls:
        return _check_result(
            "CHK-14", "Session Limits", False, CheckSeverity.ERROR,
            "SESSION_TOOL_CALLS_EXCEEDED", f"Tool calls {current_calls} >= limit {max_calls}",
        )

    max_dur = session_limits.get("max_session_duration_minutes")
    current_dur = context.get("session_duration_minutes", 0)
    if max_dur and current_dur >= max_dur:
        return _check_result(
            "CHK-14", "Session Limits", False, CheckSeverity.ERROR,
            "SESSION_DURATION_EXCEEDED", f"Session duration {current_dur}m >= limit {max_dur}m",
        )

    return _check_result("CHK-14", "Session Limits", True, message="Session limits check passed")


def chk_15_approval(
    credential: dict[str, Any],
    action: dict[str, Any],
    mode: EnforcementMode = EnforcementMode.STATELESS,
    live_mandate: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    if mode == EnforcementMode.STATELESS:
        return _check_result(
            "CHK-15", "Approval", True,
            CheckSeverity.INFO, message="Approval check skipped in stateless mode",
        )

    approval_mode = credential.get("approval_mode", "autonomous")
    if approval_mode == "autonomous":
        return _check_result("CHK-15", "Approval", True, message="Autonomous mode — no approval required")

    verb = action.get("verb", "")
    core_verbs = credential.get("core_verbs", {})
    policy = core_verbs.get(verb, {})
    if isinstance(policy, dict) and policy.get("requires_approval", False):
        return _check_result(
            "CHK-15", "Approval", False, CheckSeverity.WARNING,
            "APPROVAL_REQUIRED", f"Action '{verb}' requires approval",
            details={"approval_mode": approval_mode},
        )

    return _check_result("CHK-15", "Approval", True, message="Approval check passed")


def chk_16_delegation(credential: dict[str, Any], context: dict[str, Any], **_: Any) -> dict[str, Any]:
    chain = credential.get("delegation_chain", [])
    if not chain:
        return _check_result("CHK-16", "Delegation Chain", True, message="No delegation chain")

    agent_id = context.get("agent_id", "")
    last_entry = chain[-1]
    last_delegate = last_entry.get("delegate", "")
    if agent_id and last_delegate and agent_id != last_delegate:
        return _check_result(
            "CHK-16", "Delegation Chain", False, CheckSeverity.ERROR,
            "DELEGATION_AGENT_MISMATCH",
            f"Presenting agent '{agent_id}' does not match last delegate '{last_delegate}'",
        )

    for i in range(1, len(chain)):
        prev_remaining = chain[i - 1].get("max_depth_remaining", 0)
        curr_remaining = chain[i].get("max_depth_remaining", 0)
        if curr_remaining > prev_remaining - 1:
            return _check_result(
                "CHK-16", "Delegation Chain", False, CheckSeverity.ERROR,
                "DELEGATION_DEPTH_EXCEEDED",
                f"Delegation depth violation at chain entry {i}",
            )

    if any(entry.get("max_depth_remaining", 0) < 0 for entry in chain):
        return _check_result(
            "CHK-16", "Delegation Chain", False, CheckSeverity.ERROR,
            "DELEGATION_DEPTH_EXCEEDED", "Negative max_depth_remaining in chain",
        )

    return _check_result("CHK-16", "Delegation Chain", True, message="Delegation chain valid")


CHECKS_REGISTRY = [
    ("CHK-01", chk_01_credential),
    ("CHK-02", chk_02_temporal),
    ("CHK-03", chk_03_profile),
    ("CHK-04", chk_04_phase),
    ("CHK-05", chk_05_sector),
    ("CHK-06", chk_06_region),
    ("CHK-07", chk_07_path),
    ("CHK-08", chk_08_verb),
    ("CHK-09", chk_09_constraints),
    ("CHK-10", chk_10_platform),
    ("CHK-11", chk_11_transaction),
    ("CHK-12", chk_12_decision),
    ("CHK-13", chk_13_budget),
    ("CHK-14", chk_14_session),
    ("CHK-15", chk_15_approval),
    ("CHK-16", chk_16_delegation),
]
