"""GAuth enumerations — all protocol-level enum types."""

from enum import Enum


class GovernanceProfile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    ENTERPRISE = "enterprise"
    BEHOERDE = "behoerde"


class MandateStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    SUPERSEDED = "SUPERSEDED"
    DELETED = "DELETED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


TERMINAL_STATUSES = frozenset({
    MandateStatus.EXPIRED,
    MandateStatus.REVOKED,
    MandateStatus.BUDGET_EXCEEDED,
    MandateStatus.SUPERSEDED,
    MandateStatus.DELETED,
})


class ApprovalMode(str, Enum):
    AUTONOMOUS = "autonomous"
    SUPERVISED = "supervised"
    FOUR_EYES = "four-eyes"


APPROVAL_MODE_RANK = {
    ApprovalMode.AUTONOMOUS: 0,
    ApprovalMode.SUPERVISED: 1,
    ApprovalMode.FOUR_EYES: 2,
}


class Phase(str, Enum):
    PLAN = "plan"
    BUILD = "build"
    RUN = "run"


class OperationType(str, Enum):
    CREATE = "CREATE"
    ACTIVATE = "ACTIVATE"
    REVOKE = "REVOKE"
    SUSPEND = "SUSPEND"
    RESUME = "RESUME"
    BUDGET_INCREASE = "BUDGET_INCREASE"
    BUDGET_CONSUME = "BUDGET_CONSUME"
    TTL_EXTEND = "TTL_EXTEND"
    DELEGATE = "DELEGATE"
    DELETE = "DELETE"
    SUPERSEDE = "SUPERSEDE"
    DELEGATION_APPROVE = "DELEGATION_APPROVE"
    DELEGATION_REJECT = "DELEGATION_REJECT"


class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    CONSTRAIN = "CONSTRAIN"


class EnforcementMode(str, Enum):
    STATELESS = "stateless"
    STATEFUL = "stateful"


class CheckSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ManagementErrorCode(str, Enum):
    MANDATE_NOT_FOUND = "MANDATE_NOT_FOUND"
    PROFILE_NOT_FOUND = "PROFILE_NOT_FOUND"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    CEILING_VIOLATION = "CEILING_VIOLATION"
    CONSISTENCY_CHECK_FAILED = "CONSISTENCY_CHECK_FAILED"
    INSUFFICIENT_AUTHORITY = "INSUFFICIENT_AUTHORITY"
    MANDATE_NOT_DRAFT = "MANDATE_NOT_DRAFT"
    MANDATE_NOT_ACTIVE = "MANDATE_NOT_ACTIVE"
    MANDATE_NOT_SUSPENDED = "MANDATE_NOT_SUSPENDED"
    MANDATE_EXPIRED = "MANDATE_EXPIRED"
    BUDGET_DECREASE_NOT_ALLOWED = "BUDGET_DECREASE_NOT_ALLOWED"
    TTL_DECREASE_NOT_ALLOWED = "TTL_DECREASE_NOT_ALLOWED"
    DELEGATION_DEPTH_EXCEEDED = "DELEGATION_DEPTH_EXCEEDED"
    DELEGATION_SCOPE_WIDENING = "DELEGATION_SCOPE_WIDENING"
    DELEGATION_BUDGET_EXCEEDED = "DELEGATION_BUDGET_EXCEEDED"
    DELEGATION_TTL_EXCEEDED = "DELEGATION_TTL_EXCEEDED"
    PARENT_MANDATE_NOT_ACTIVE = "PARENT_MANDATE_NOT_ACTIVE"
    DUPLICATE_MANDATE = "DUPLICATE_MANDATE"
    DUPLICATE_CONSUMPTION_REPORT = "DUPLICATE_CONSUMPTION_REPORT"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TARIFF_GATE_DENIED = "TARIFF_GATE_DENIED"
    LICENSE_REQUIRED = "LICENSE_REQUIRED"
    ATTESTATION_REQUIRED = "ATTESTATION_REQUIRED"
    MANDATORY_SLOT_EMPTY = "MANDATORY_SLOT_EMPTY"
    LICENSE_COMPLIANCE_VIOLATION = "LICENSE_COMPLIANCE_VIOLATION"
    APPROVAL_REQUIRED_FOR_DELEGATION = "APPROVAL_REQUIRED_FOR_DELEGATION"
    DELEGATION_APPROVAL_FAILED = "DELEGATION_APPROVAL_FAILED"
    DELEGATION_ALREADY_APPROVED = "DELEGATION_ALREADY_APPROVED"
    DELEGATION_NOT_PENDING = "DELEGATION_NOT_PENDING"
    CONSTRAINT_VIOLATED = "CONSTRAINT_VIOLATED"
    OAUTH_TOKEN_INVALID = "OAUTH_TOKEN_INVALID"


ERROR_CODE_HTTP_STATUS: dict[ManagementErrorCode, int] = {
    ManagementErrorCode.MANDATE_NOT_FOUND: 404,
    ManagementErrorCode.PROFILE_NOT_FOUND: 404,
    ManagementErrorCode.INVALID_STATE_TRANSITION: 409,
    ManagementErrorCode.SCHEMA_VALIDATION_FAILED: 422,
    ManagementErrorCode.CEILING_VIOLATION: 422,
    ManagementErrorCode.CONSISTENCY_CHECK_FAILED: 422,
    ManagementErrorCode.INSUFFICIENT_AUTHORITY: 403,
    ManagementErrorCode.MANDATE_NOT_DRAFT: 409,
    ManagementErrorCode.MANDATE_NOT_ACTIVE: 409,
    ManagementErrorCode.MANDATE_NOT_SUSPENDED: 409,
    ManagementErrorCode.MANDATE_EXPIRED: 409,
    ManagementErrorCode.BUDGET_DECREASE_NOT_ALLOWED: 422,
    ManagementErrorCode.TTL_DECREASE_NOT_ALLOWED: 422,
    ManagementErrorCode.DELEGATION_DEPTH_EXCEEDED: 422,
    ManagementErrorCode.DELEGATION_SCOPE_WIDENING: 422,
    ManagementErrorCode.DELEGATION_BUDGET_EXCEEDED: 422,
    ManagementErrorCode.DELEGATION_TTL_EXCEEDED: 422,
    ManagementErrorCode.PARENT_MANDATE_NOT_ACTIVE: 409,
    ManagementErrorCode.DUPLICATE_MANDATE: 409,
    ManagementErrorCode.DUPLICATE_CONSUMPTION_REPORT: 409,
    ManagementErrorCode.RATE_LIMITED: 429,
    ManagementErrorCode.INTERNAL_ERROR: 500,
    ManagementErrorCode.TARIFF_GATE_DENIED: 403,
    ManagementErrorCode.LICENSE_REQUIRED: 403,
    ManagementErrorCode.ATTESTATION_REQUIRED: 403,
    ManagementErrorCode.MANDATORY_SLOT_EMPTY: 422,
    ManagementErrorCode.LICENSE_COMPLIANCE_VIOLATION: 403,
    ManagementErrorCode.APPROVAL_REQUIRED_FOR_DELEGATION: 202,
    ManagementErrorCode.DELEGATION_APPROVAL_FAILED: 403,
    ManagementErrorCode.DELEGATION_ALREADY_APPROVED: 409,
    ManagementErrorCode.DELEGATION_NOT_PENDING: 409,
    ManagementErrorCode.CONSTRAINT_VIOLATED: 403,
    ManagementErrorCode.OAUTH_TOKEN_INVALID: 401,
}


class ShellMode(str, Enum):
    ANY = "any"
    DENYLIST = "denylist"
    ALLOWLIST = "allowlist"


class Tariff(str, Enum):
    O = "O"
    S = "S"
    M = "M"
    L = "L"
    MO = "M+O"
    LO = "L+O"


TARIFF_ADAPTER_ACCESS = {
    Tariff.O: "O",
    Tariff.S: "S",
    Tariff.M: "M",
    Tariff.L: "L",
    Tariff.MO: "M",
    Tariff.LO: "L",
}


def tariff_effective_level(tariff: Tariff) -> str:
    return TARIFF_ADAPTER_ACCESS.get(tariff, "O")


def is_open_core_active(tariff: Tariff) -> bool:
    return tariff in (Tariff.MO, Tariff.LO)


SLOT_TYPE_CLASSIFICATION: dict[str, str] = {
    "pdp": "A",
    "oauth_engine": "A",
    "foundry": "B",
    "wallet": "B",
    "ai_governance": "C",
    "web3_identity": "C",
    "dna_identity": "C",
}

TYPE_C_SLOTS = frozenset(
    slot for slot, cls in SLOT_TYPE_CLASSIFICATION.items() if cls == "C"
)

DEPLOYMENT_POLICY_MATRIX: dict[str, dict[str, str]] = {
    "pdp":            {"O": "active_always", "S": "active_always", "M": "active_always", "L": "active_always"},
    "oauth_engine":   {"O": "user_provided_required", "S": "gimel_or_user", "M": "gimel_or_user", "L": "gimel_or_user"},
    "foundry":        {"O": "null_or_user", "S": "gimel_or_user", "M": "gimel_or_user", "L": "gimel_or_user"},
    "wallet":         {"O": "null_or_user", "S": "gimel_or_user", "M": "gimel_or_user", "L": "gimel_or_user"},
    "ai_governance":  {"O": "null", "S": "null", "M": "attested_gimel", "L": "attested_gimel"},
    "web3_identity":  {"O": "null", "S": "null", "M": "null_or_attested_gimel", "L": "attested_gimel"},
    "dna_identity":   {"O": "null", "S": "null", "M": "null", "L": "attested_gimel"},
}


class TariffGateResult:
    __slots__ = ("allowed", "availability", "reason")

    def __init__(self, allowed: bool, availability: str, reason: str = ""):
        self.allowed = allowed
        self.availability = availability
        self.reason = reason


def check_tariff_gate(slot_name: str, tariff: Tariff) -> TariffGateResult:
    effective = tariff_effective_level(tariff)
    matrix = DEPLOYMENT_POLICY_MATRIX.get(slot_name)
    if matrix is None:
        return TariffGateResult(False, "null", f"Unknown slot: {slot_name}")
    availability = matrix.get(effective, "null")
    if availability == "null":
        return TariffGateResult(
            False, "null",
            f"Slot '{slot_name}' not available for tariff {tariff.value} (effective level {effective})",
        )
    return TariffGateResult(True, availability)
