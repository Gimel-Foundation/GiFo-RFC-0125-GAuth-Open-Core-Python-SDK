import { pgEnum } from "drizzle-orm/pg-core";

export const governanceProfileValues = [
  "minimal",
  "standard",
  "strict",
  "enterprise",
  "behoerde",
] as const;
export type GovernanceProfile = (typeof governanceProfileValues)[number];
export const governanceProfileEnum = pgEnum(
  "governance_profile",
  governanceProfileValues,
);

export const mandateStatusValues = [
  "DRAFT",
  "ACTIVE",
  "SUSPENDED",
  "EXPIRED",
  "REVOKED",
  "BUDGET_EXCEEDED",
  "SUPERSEDED",
  "DELETED",
] as const;
export type MandateStatus = (typeof mandateStatusValues)[number];
export const mandateStatusEnum = pgEnum("mandate_status", mandateStatusValues);

export const TERMINAL_STATUSES: ReadonlySet<MandateStatus> = new Set([
  "EXPIRED",
  "REVOKED",
  "BUDGET_EXCEEDED",
  "SUPERSEDED",
  "DELETED",
]);

export const approvalModeValues = [
  "autonomous",
  "supervised",
  "four-eyes",
] as const;
export type ApprovalMode = (typeof approvalModeValues)[number];
export const approvalModeEnum = pgEnum("approval_mode", approvalModeValues);

export const APPROVAL_MODE_RANK: Record<ApprovalMode, number> = {
  autonomous: 0,
  supervised: 1,
  "four-eyes": 2,
};

export const phaseValues = ["plan", "build", "run"] as const;
export type Phase = (typeof phaseValues)[number];
export const phaseEnum = pgEnum("phase", phaseValues);

export const operationTypeValues = [
  "CREATE",
  "ACTIVATE",
  "REVOKE",
  "SUSPEND",
  "RESUME",
  "BUDGET_INCREASE",
  "BUDGET_CONSUME",
  "TTL_EXTEND",
  "DELEGATE",
  "DELETE",
  "SUPERSEDE",
] as const;
export type OperationType = (typeof operationTypeValues)[number];
export const operationTypeEnum = pgEnum("operation_type", operationTypeValues);

export const decisionValues = ["PERMIT", "DENY", "CONSTRAIN"] as const;
export type Decision = (typeof decisionValues)[number];

export const enforcementModeValues = ["stateless", "stateful"] as const;
export type EnforcementMode = (typeof enforcementModeValues)[number];

export const checkSeverityValues = ["error", "warning", "info"] as const;
export type CheckSeverity = (typeof checkSeverityValues)[number];

export const shellModeValues = ["any", "denylist", "allowlist"] as const;
export type ShellMode = (typeof shellModeValues)[number];
