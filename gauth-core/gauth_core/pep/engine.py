"""PEP evaluation engine — ordered pipeline, two-pass delegation, mode selection, hybrid cascade."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger(__name__)

from gauth_core.adapters.registry import AdapterRegistry, _is_noop
from gauth_core.pep.checks import (
    CHECKS_REGISTRY,
    chk_05_sector,
    chk_06_region,
    chk_07_path,
    chk_08_verb,
    chk_09_constraints,
    chk_10_platform,
    chk_11_transaction,
    chk_12_decision,
    chk_16_delegation,
)
from gauth_core.profiles.ceilings import get_ceiling, GovernanceProfile
from gauth_core.schema.enums import CheckSeverity, Decision, EnforcementMode
from gauth_core.storage.base import MandateRepository


class AuthPEPClient(Protocol):
    def escalate(self, request: dict[str, Any]) -> dict[str, Any]:
        ...


DELEGATION_REEVAL_CHECKS = [
    ("CHK-05", chk_05_sector),
    ("CHK-06", chk_06_region),
    ("CHK-07", chk_07_path),
    ("CHK-08", chk_08_verb),
    ("CHK-09", chk_09_constraints),
    ("CHK-10", chk_10_platform),
    ("CHK-11", chk_11_transaction),
    ("CHK-12", chk_12_decision),
]


class PEPEngine:

    def __init__(
        self,
        repository: MandateRepository | None = None,
        adapter_registry: AdapterRegistry | None = None,
        auth_pep_client: AuthPEPClient | None = None,
    ) -> None:
        self._repo = repository
        self._adapters = adapter_registry or AdapterRegistry(allow_untrusted=False)
        self._auth_pep = auth_pep_client
        self._compliance_violations: list[dict[str, Any]] = []
        self._validate_adapter_compliance()

    def _validate_adapter_compliance(self) -> None:
        self._compliance_violations = self._adapters.validate_tariff_compliance()
        if self._compliance_violations:
            for v in self._compliance_violations:
                logger.warning(
                    "PEPEngine init: LICENSE_COMPLIANCE_VIOLATION — "
                    "adapter '%s' in slot '%s' not permitted on tariff %s",
                    v.get("adapter_class"), v.get("slot"), v.get("tariff"),
                )

    @property
    def compliance_violations(self) -> list[dict[str, Any]]:
        return list(self._compliance_violations)

    def _is_adapter_compliant(self, adapter_type: str) -> bool:
        return self._adapters.is_adapter_compliant(adapter_type)

    def _select_mode(self, credential: dict[str, Any], action: dict[str, Any]) -> EnforcementMode:
        profile_name = credential.get("governance_profile", "minimal")
        try:
            ceiling = get_ceiling(profile_name)
            if profile_name == GovernanceProfile.BEHOERDE.value:
                return EnforcementMode.STATEFUL
        except ValueError:
            pass

        verb = action.get("verb", "")
        read_verbs = {"read", "get", "list", "query", "search", "view", "inspect"}
        is_read = any(rv in verb.lower() for rv in read_verbs)
        has_budget_impact = action.get("parameters", {}).get("estimated_cost_cents", 0) > 0
        approval = credential.get("approval_mode", "autonomous")

        if is_read and not has_budget_impact and approval == "autonomous":
            return EnforcementMode.STATELESS

        return EnforcementMode.STATEFUL

    def _compute_effective_scope(self, credential: dict[str, Any]) -> dict[str, Any] | None:
        chain = credential.get("delegation_chain", [])
        if not chain:
            return None

        effective: dict[str, Any] = {}
        for key in ["allowed_sectors", "allowed_regions", "allowed_paths",
                     "allowed_transactions", "allowed_decisions"]:
            effective[key] = list(credential.get(key, []))

        effective["core_verbs"] = dict(credential.get("core_verbs", {}))
        effective["platform_permissions"] = dict(credential.get("platform_permissions", {}))
        effective["denied_paths"] = list(credential.get("denied_paths", []))

        for entry in chain:
            restriction = entry.get("scope_restriction", {})
            for key in ["allowed_sectors", "allowed_regions", "allowed_paths",
                        "allowed_transactions", "allowed_decisions"]:
                if key in restriction:
                    current = set(effective.get(key, []))
                    restricted = set(restriction[key])
                    effective[key] = sorted(current & restricted) if current else sorted(restricted)

            if "denied_paths" in restriction:
                effective["denied_paths"] = list(
                    set(effective.get("denied_paths", [])) | set(restriction["denied_paths"])
                )

            if "core_verbs" in restriction:
                restricted_verbs = restriction["core_verbs"]
                current_verbs = effective.get("core_verbs", {})
                narrowed = {}
                for k, v in current_verbs.items():
                    if k in restricted_verbs:
                        narrowed[k] = restricted_verbs[k]
                effective["core_verbs"] = narrowed

        return effective

    def _oauth_pre_check(
        self,
        request_id: str,
        credential: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        oauth_adapter = self._adapters.oauth_engine
        if _is_noop(oauth_adapter):
            return None

        if not self._is_adapter_compliant("oauth_engine"):
            return None

        oauth_token = context.get("oauth_token") or credential.get("oauth_token", "")
        if not oauth_token:
            return None

        try:
            result = oauth_adapter.validate_token(oauth_token)
            active = result.get("active", False)
            if not active:
                return {
                    "check_id": "CHK-OAUTH",
                    "check_name": "OAuth Token Validation",
                    "result": "fail",
                    "severity": CheckSeverity.ERROR.value,
                    "violation_code": "OAUTH_TOKEN_INVALID",
                    "message": "OAuth token validation failed — token is not active",
                    "details": {"oauth_result": result},
                }
        except Exception as exc:
            return {
                "check_id": "CHK-OAUTH",
                "check_name": "OAuth Token Validation",
                "result": "fail",
                "severity": CheckSeverity.ERROR.value,
                "violation_code": "OAUTH_TOKEN_INVALID",
                "message": f"OAuth token validation error: {exc}",
                "details": {},
            }

        return None

    def enforce_action(
        self,
        request_id: str | None = None,
        credential: dict[str, Any] | None = None,
        action: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        start_time = time.monotonic()
        now = datetime.now(timezone.utc)

        if request:
            request_id = request.get("request_id", request_id or str(uuid.uuid4()))
            credential = request.get("credential", credential or {})
            action = request.get("action", action or {})
            context = request.get("context", context or {})

        if not request_id:
            request_id = str(uuid.uuid4())
        credential = credential or {}
        action = action or {}
        context = context or {}

        oauth_denial = self._oauth_pre_check(request_id, credential, context)
        if oauth_denial:
            return {
                "request_id": request_id,
                "decision": Decision.DENY.value,
                "checks": [oauth_denial],
                "enforced_constraints": [],
                "violations": [oauth_denial],
                "audit": {
                    "request_id": request_id,
                    "credential_ref": credential.get("mandate_id", ""),
                    "enforcement_mode": "pre_check",
                    "processing_time_ms": round((time.monotonic() - start_time) * 1000, 2),
                    "pep_interface_version": "1.1",
                    "timestamp": now.isoformat(),
                    "checks_evaluated": 1,
                },
            }

        requested_mode = context.get("enforcement_mode")
        if requested_mode:
            try:
                mode = EnforcementMode(requested_mode)
            except ValueError:
                mode = self._select_mode(credential, action)
        else:
            mode = self._select_mode(credential, action)

        live_mandate = None
        stateful_mandate_missing = False
        if mode == EnforcementMode.STATEFUL:
            mandate_id = credential.get("mandate_id", "")
            if not self._repo:
                stateful_mandate_missing = True
            elif mandate_id:
                live_mandate = self._repo.get(mandate_id)
                if live_mandate is None:
                    stateful_mandate_missing = True
            else:
                stateful_mandate_missing = True

        if stateful_mandate_missing:
            return {
                "request_id": request_id,
                "decision": Decision.DENY.value,
                "checks": [{
                    "check_id": "CHK-00",
                    "check_name": "Stateful Mandate Lookup",
                    "result": "fail",
                    "severity": CheckSeverity.ERROR.value,
                    "violation_code": "STATEFUL_MANDATE_NOT_FOUND",
                    "message": "Stateful enforcement requires a valid live mandate but none was found",
                    "details": {"mandate_id": credential.get("mandate_id", "")},
                }],
                "enforced_constraints": [],
                "violations": [{
                    "check_id": "CHK-00",
                    "check_name": "Stateful Mandate Lookup",
                    "result": "fail",
                    "severity": CheckSeverity.ERROR.value,
                    "violation_code": "STATEFUL_MANDATE_NOT_FOUND",
                    "message": "Stateful enforcement requires a valid live mandate but none was found",
                    "details": {"mandate_id": credential.get("mandate_id", "")},
                }],
                "audit": {
                    "request_id": request_id,
                    "credential_ref": credential.get("mandate_id", ""),
                    "enforcement_mode": mode.value,
                    "processing_time_ms": round((time.monotonic() - start_time) * 1000, 2),
                    "pep_interface_version": "1.1",
                    "timestamp": now.isoformat(),
                    "checks_evaluated": 1,
                },
            }

        enrichment = {}
        if self._is_adapter_compliant("ai_enrichment"):
            try:
                enrichment = self._adapters.ai_enrichment.enrich(
                    {"request_id": request_id, "credential": credential, "action": action, "context": context},
                    live_mandate or credential,
                )
            except Exception:
                pass

        all_checks: list[dict[str, Any]] = []
        for check_id, check_fn in CHECKS_REGISTRY:
            try:
                result = check_fn(
                    credential=credential,
                    action=action,
                    context=context,
                    mode=mode,
                    live_mandate=live_mandate,
                )
                all_checks.append(result)
            except Exception as e:
                all_checks.append({
                    "check_id": check_id,
                    "check_name": f"Check {check_id}",
                    "result": "fail",
                    "severity": CheckSeverity.ERROR.value,
                    "violation_code": "CHECK_INTERNAL_ERROR",
                    "message": str(e),
                    "details": {},
                })

        effective_scope = None
        delegation_chain = credential.get("delegation_chain", [])
        if delegation_chain:
            effective_scope = self._compute_effective_scope(credential)
            if effective_scope:
                narrowed_credential = {**credential, **effective_scope}
                for check_id, check_fn in DELEGATION_REEVAL_CHECKS:
                    try:
                        result = check_fn(
                            credential=narrowed_credential,
                            action=action,
                            context=context,
                            mode=mode,
                            live_mandate=None,
                        )
                        result["check_id"] = f"{check_id}-D"
                        result["check_name"] = f"{result['check_name']} (delegated scope)"
                        all_checks.append(result)
                    except Exception as e:
                        all_checks.append({
                            "check_id": f"{check_id}-D",
                            "check_name": f"Check {check_id} (delegated scope)",
                            "result": "fail",
                            "severity": CheckSeverity.ERROR.value,
                            "violation_code": "CHECK_INTERNAL_ERROR",
                            "message": str(e),
                            "details": {},
                        })

        violations = [
            c for c in all_checks
            if c["result"] == "fail" and c["severity"] == CheckSeverity.ERROR.value
        ]
        warnings = [
            c for c in all_checks
            if c["result"] == "fail" and c["severity"] == CheckSeverity.WARNING.value
        ]

        constraints: list[dict[str, Any]] = []
        for c in all_checks:
            details = c.get("details", {})
            if details.get("constraints"):
                constraints.append({
                    "constraint_type": "verb_constraint",
                    "source_check": c["check_id"],
                    "parameters": details["constraints"],
                    "message": c.get("message", ""),
                })
        for w in warnings:
            if w.get("violation_code") == "APPROVAL_REQUIRED":
                constraints.append({
                    "constraint_type": "approval_required",
                    "source_check": w["check_id"],
                    "parameters": w.get("details", {}),
                    "message": w.get("message", ""),
                })

        if violations:
            decision = Decision.DENY
        elif constraints:
            decision = Decision.CONSTRAIN
        else:
            decision = Decision.PERMIT

        if decision == Decision.CONSTRAIN and self._auth_pep is not None:
            decision, all_checks, constraints = self._escalate_to_auth_pep(
                request_id=request_id,
                credential=credential,
                action=action,
                context=context,
                local_checks=all_checks,
                local_constraints=constraints,
                decision=decision,
            )
            violations = [
                c for c in all_checks
                if c["result"] == "fail" and c["severity"] == CheckSeverity.ERROR.value
            ]

        processing_time = (time.monotonic() - start_time) * 1000

        compliance = {}
        if decision != Decision.DENY and self._is_adapter_compliant("compliance_enrichment"):
            try:
                decision_dict = {"decision": decision.value, "request_id": request_id}
                request_dict = {"credential": credential, "action": action, "context": context}
                compliance = self._adapters.compliance_enrichment.evaluate(decision_dict, request_dict)
            except Exception:
                pass

        result = {
            "request_id": request_id,
            "decision": decision.value,
            "checks": all_checks,
            "enforced_constraints": constraints,
            "violations": violations,
            "audit": {
                "request_id": request_id,
                "credential_ref": credential.get("jti", credential.get("mandate_id", "")),
                "enforcement_mode": mode.value,
                "processing_time_ms": round(processing_time, 2),
                "pep_interface_version": "1.1",
                "timestamp": now.isoformat(),
                "checks_evaluated": len(all_checks),
            },
        }

        if effective_scope:
            result["effective_scope"] = effective_scope

        if enrichment and enrichment.get("enrichment_source") != "noop":
            result["audit"]["enrichment"] = enrichment

        if compliance and compliance.get("source") != "noop":
            result["compliance_enrichment"] = compliance

        return result

    def _escalate_to_auth_pep(
        self,
        request_id: str,
        credential: dict[str, Any],
        action: dict[str, Any],
        context: dict[str, Any],
        local_checks: list[dict[str, Any]],
        local_constraints: list[dict[str, Any]],
        decision: Decision,
    ) -> tuple[Decision, list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            escalation_request = {
                "request_id": request_id,
                "credential": credential,
                "action": action,
                "context": context,
                "local_decision": decision.value,
                "local_constraints": local_constraints,
            }
            auth_result = self._auth_pep.escalate(escalation_request)
            auth_decision_str = auth_result.get("decision", "")
            try:
                auth_decision = Decision(auth_decision_str)
            except ValueError:
                auth_decision = Decision.DENY

            escalation_check = {
                "check_id": "CHK-ESC",
                "check_name": "Auth PEP Escalation",
                "result": "pass" if auth_decision != Decision.DENY else "fail",
                "severity": CheckSeverity.INFO.value if auth_decision != Decision.DENY else CheckSeverity.ERROR.value,
                "violation_code": None if auth_decision != Decision.DENY else "AUTH_PEP_DENIED",
                "message": f"Auth PEP resolved CONSTRAIN → {auth_decision.value}",
                "details": {"auth_pep_decision": auth_decision.value, "escalation": True},
            }
            local_checks.append(escalation_check)

            if auth_decision == Decision.PERMIT:
                local_constraints = []

            return auth_decision, local_checks, local_constraints

        except Exception as exc:
            fallback_check = {
                "check_id": "CHK-ESC",
                "check_name": "Auth PEP Escalation",
                "result": "fail",
                "severity": CheckSeverity.WARNING.value,
                "violation_code": "AUTH_PEP_UNREACHABLE",
                "message": f"Auth PEP unreachable, rule-based-only fallback: {exc}",
                "details": {"escalation": True, "fallback": "CONSTRAIN"},
            }
            local_checks.append(fallback_check)
            return decision, local_checks, local_constraints

    def batch_enforce(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.enforce_action(request=req) for req in requests]

    def get_enforcement_policy(self) -> dict[str, Any]:
        return {
            "pep_interface_version": "1.1",
            "supported_checks": [cid for cid, _ in CHECKS_REGISTRY],
            "enforcement_modes": ["stateless", "stateful"],
            "fail_mode": "closed",
            "delegation_evaluation": "two_pass",
            "hybrid_cascade": self._auth_pep is not None,
        }

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "pep_interface_version": "1.1",
            "checks_count": len(CHECKS_REGISTRY),
            "adapters": self._adapters.list_registered(),
        }
