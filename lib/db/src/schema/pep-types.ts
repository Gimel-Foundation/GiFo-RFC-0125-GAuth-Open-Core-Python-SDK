import { z } from "zod/v4";
import {
  governanceProfileValues,
  mandateStatusValues,
  approvalModeValues,
  phaseValues,
  decisionValues,
  enforcementModeValues,
  checkSeverityValues,
} from "./enums";

export const enforcementActionSchema = z.object({
  verb: z.string().min(1),
  resource: z.string().default(""),
  parameters: z.record(z.string(), z.unknown()).default({}),
});
export type EnforcementAction = z.infer<typeof enforcementActionSchema>;

export const enforcementContextSchema = z.object({
  agent_id: z.string().min(1),
  session_id: z.string().default(""),
  timestamp: z.string().default(() => new Date().toISOString()),
  enforcement_mode: z.enum(enforcementModeValues).optional(),
  tool_call_count: z.number().int().min(0).default(0),
  lines_changed: z.number().int().min(0).default(0),
  budget_impact_cents: z.number().int().min(0).default(0),
  sector: z.string().optional(),
  region: z.string().optional(),
  decision_type: z.string().optional(),
  transaction_type: z.string().optional(),
});
export type EnforcementContext = z.infer<typeof enforcementContextSchema>;

export const poaCredentialInputSchema = z.object({
  mandate_id: z.string().min(1),
  subject: z.string().min(1),
  governance_profile: z.enum(governanceProfileValues),
  phase: z.enum(phaseValues),
  jti: z.string().default(""),
  core_verbs: z.record(z.string(), z.unknown()).default({}),
  platform_permissions: z.record(z.string(), z.unknown()).default({}),
  allowed_paths: z.array(z.string()).default([]),
  denied_paths: z.array(z.string()).default([]),
  allowed_sectors: z.array(z.string()).default([]),
  allowed_regions: z.array(z.string()).default([]),
  allowed_transactions: z.array(z.string()).default([]),
  allowed_decisions: z.array(z.string()).default([]),
  approval_mode: z.enum(approvalModeValues).default("autonomous"),
  budget_total_cents: z.number().int().min(0).default(0),
  budget_remaining_cents: z.number().int().min(0).default(0),
  ttl_seconds: z.number().int().min(0).default(0),
  exp: z.string().nullable().default(null),
  nbf: z.string().nullable().default(null),
  scope_checksum: z.string().default(""),
  tool_permissions_hash: z.string().default(""),
  platform_permissions_hash: z.string().default(""),
  status: z.enum(mandateStatusValues).default("ACTIVE"),
  delegation_chain: z.array(z.object({
    delegator: z.string(),
    delegate: z.string(),
    scope_restriction: z.record(z.string(), z.unknown()).default({}),
    delegated_at: z.string(),
    max_depth_remaining: z.number().int().min(0).default(0),
  })).default([]),
  session_limits: z.object({
    max_tool_calls: z.number().int().positive().nullable().default(null),
    max_session_duration_minutes: z.number().int().positive().nullable().default(null),
    max_lines_per_commit: z.number().int().positive().nullable().default(null),
  }).default({ max_tool_calls: null, max_session_duration_minutes: null, max_lines_per_commit: null }),
});
export type PoACredentialInput = z.infer<typeof poaCredentialInputSchema>;

export const enforcementRequestSchema = z.object({
  request_id: z.string().min(1),
  credential: poaCredentialInputSchema,
  action: enforcementActionSchema,
  context: enforcementContextSchema,
});
export type EnforcementRequest = z.infer<typeof enforcementRequestSchema>;

export const checkResultSchema = z.object({
  check_id: z.string(),
  name: z.string(),
  result: z.enum(["pass", "fail", "skip", "warn"]),
  severity: z.enum(checkSeverityValues),
  violation_code: z.string().nullable().default(null),
  message: z.string().default(""),
  details: z.record(z.string(), z.unknown()).default({}),
});
export type CheckResult = z.infer<typeof checkResultSchema>;

export const enforcedConstraintSchema = z.object({
  type: z.string(),
  description: z.string(),
  parameters: z.record(z.string(), z.unknown()).default({}),
});
export type EnforcedConstraint = z.infer<typeof enforcedConstraintSchema>;

export const auditRecordSchema = z.object({
  request_id: z.string(),
  credential_ref: z.string(),
  enforcement_mode: z.enum(enforcementModeValues),
  pep_interface_version: z.string(),
  processing_time_ms: z.number(),
  decision: z.enum(decisionValues),
  checks_run: z.number().int(),
  checks_passed: z.number().int(),
  checks_failed: z.number().int(),
  timestamp: z.string(),
});
export type AuditRecord = z.infer<typeof auditRecordSchema>;

export const enforcementDecisionSchema = z.object({
  request_id: z.string(),
  decision: z.enum(decisionValues),
  checks: z.array(checkResultSchema),
  enforced_constraints: z.array(enforcedConstraintSchema).default([]),
  violations: z.array(z.object({
    check_id: z.string(),
    violation_code: z.string(),
    message: z.string(),
  })).default([]),
  effective_scope: z.record(z.string(), z.unknown()).optional(),
  audit: auditRecordSchema,
});
export type EnforcementDecision = z.infer<typeof enforcementDecisionSchema>;

export const batchEnforcementRequestSchema = z.object({
  requests: z.array(enforcementRequestSchema).min(1).max(50),
});
export type BatchEnforcementRequest = z.infer<typeof batchEnforcementRequestSchema>;

export const batchEnforcementResponseSchema = z.object({
  results: z.array(enforcementDecisionSchema),
  total_processing_time_ms: z.number(),
});
export type BatchEnforcementResponse = z.infer<typeof batchEnforcementResponseSchema>;

export const PEP_INTERFACE_VERSION = "1.1";

export const violationCodes = {
  CREDENTIAL_INVALID: "V-001",
  CREDENTIAL_EXPIRED: "V-002",
  CREDENTIAL_NOT_YET_VALID: "V-003",
  MANDATE_NOT_ACTIVE: "V-004",
  GOVERNANCE_PROFILE_VIOLATION: "V-005",
  PHASE_MISMATCH: "V-006",
  SECTOR_NOT_ALLOWED: "V-007",
  REGION_NOT_ALLOWED: "V-008",
  PATH_DENIED: "V-009",
  PATH_NOT_ALLOWED: "V-010",
  VERB_NOT_AUTHORIZED: "V-011",
  VERB_NOT_ALLOWED: "V-012",
  CONSTRAINT_VIOLATION: "V-013",
  PLATFORM_PERMISSION_DENIED: "V-014",
  PLATFORM_HASH_MISMATCH: "V-015",
  TRANSACTION_NOT_ALLOWED: "V-016",
  DECISION_TYPE_NOT_ALLOWED: "V-017",
  BUDGET_INSUFFICIENT: "V-018",
  BUDGET_STALE_WARNING: "V-019",
  SESSION_TOOL_CALLS_EXCEEDED: "V-020",
  SESSION_DURATION_EXCEEDED: "V-021",
  SESSION_LINES_EXCEEDED: "V-022",
  APPROVAL_REQUIRED: "V-023",
  DELEGATION_CHAIN_INVALID: "V-024",
  DELEGATION_DEPTH_EXCEEDED: "V-025",
  DELEGATION_SCOPE_WIDENED: "V-026",
  DELEGATION_EXPIRED: "V-027",
  UNKNOWN_PROFILE: "V-028",
  INTERNAL_ERROR: "V-099",
} as const;
export type ViolationCode = (typeof violationCodes)[keyof typeof violationCodes];
