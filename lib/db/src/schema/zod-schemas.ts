import { z } from "zod/v4";
import {
  governanceProfileValues,
  mandateStatusValues,
  approvalModeValues,
  phaseValues,
  operationTypeValues,
  shellModeValues,
  tariffValues,
} from "./enums";

export const governanceProfileSchema = z.enum(governanceProfileValues);
export const mandateStatusSchema = z.enum(mandateStatusValues);
export const approvalModeSchema = z.enum(approvalModeValues);
export const phaseSchema = z.enum(phaseValues);
export const operationTypeSchema = z.enum(operationTypeValues);
export const shellModeSchema = z.enum(shellModeValues);

export const toolPolicySchema = z.object({
  allowed: z.boolean().default(true),
  requires_approval: z.boolean().default(false),
  max_per_session: z.number().int().positive().nullable().default(null),
  constraints: z.record(z.string(), z.unknown()).default({}),
});
export type ToolPolicy = z.infer<typeof toolPolicySchema>;

export const platformPermissionsSchema = z.object({
  deployment_targets: z.array(z.string()).default([]),
  auto_deploy: z.boolean().default(false),
  db_write: z.boolean().default(false),
  db_migration: z.boolean().default(false),
  db_production: z.boolean().default(false),
  shell_mode: shellModeSchema.default("any"),
  packages_audited_only: z.boolean().default(false),
  secrets_read: z.boolean().default(false),
  secrets_create: z.boolean().default(false),
});
export type PlatformPermissions = z.infer<typeof platformPermissionsSchema>;

export const delegationEntrySchema = z.object({
  delegator: z.string(),
  delegate: z.string(),
  scope_restriction: z.record(z.string(), z.unknown()).default({}),
  delegated_at: z.iso.datetime(),
  max_depth_remaining: z.number().int().min(0).default(0),
});
export type DelegationEntry = z.infer<typeof delegationEntrySchema>;

export const sessionLimitsSchema = z.object({
  max_tool_calls: z.number().int().positive().nullable().default(null),
  max_session_duration_minutes: z.number().int().positive().nullable().default(null),
  max_lines_per_commit: z.number().int().positive().nullable().default(null),
});
export type SessionLimits = z.infer<typeof sessionLimitsSchema>;

export const budgetSchema = z.object({
  total_cents: z.number().int().min(0),
});
export type Budget = z.infer<typeof budgetSchema>;

export const budgetDetailSchema = z.object({
  total_cents: z.number().int().min(0),
  remaining_cents: z.number().int().min(0),
  consumed_cents: z.number().int().min(0),
  utilization_percent: z.number().min(0).max(100),
  reserved_for_delegations_cents: z.number().int().min(0).default(0),
});
export type BudgetDetail = z.infer<typeof budgetDetailSchema>;

export const mandateScopeSchema = z.object({
  governance_profile: governanceProfileSchema,
  phase: phaseSchema,
  core_verbs: z.record(z.string(), toolPolicySchema).default({}),
  platform_permissions: platformPermissionsSchema.default({
    deployment_targets: [],
    auto_deploy: false,
    db_write: false,
    db_migration: false,
    db_production: false,
    shell_mode: "any" as const,
    packages_audited_only: false,
    secrets_read: false,
    secrets_create: false,
  }),
  active_modules: z.array(z.string()).default([]),
  allowed_paths: z.array(z.string()).default([]),
  denied_paths: z.array(z.string()).default([]),
  allowed_sectors: z.array(z.string()).default([]),
  allowed_regions: z.array(z.string()).default([]),
  allowed_transactions: z.array(z.string()).default([]),
  transaction_matrix: z.record(z.string(), z.unknown()).default({}),
  allowed_decisions: z.array(z.string()).default([]),
});
export type MandateScope = z.infer<typeof mandateScopeSchema>;

export const mandateRequirementsSchema = z.object({
  approval_mode: approvalModeSchema,
  budget: budgetSchema,
  ttl_seconds: z.number().int().min(60),
  session_limits: sessionLimitsSchema.default({
    max_tool_calls: null,
    max_session_duration_minutes: null,
    max_lines_per_commit: null,
  }),
});
export type MandateRequirements = z.infer<typeof mandateRequirementsSchema>;

export const partiesSchema = z.object({
  subject: z.string().min(1),
  customer_id: z.string().min(1),
  project_id: z.string().min(1),
  issued_by: z.string().min(1),
  approval_chain: z.array(z.string()).default([]),
});
export type Parties = z.infer<typeof partiesSchema>;

export const mandateCreationRequestSchema = z.object({
  parties: partiesSchema,
  scope: mandateScopeSchema,
  requirements: mandateRequirementsSchema,
});
export type MandateCreationRequest = z.infer<typeof mandateCreationRequestSchema>;

export const mandateActivationRequestSchema = z.object({
  mandate_id: z.string().min(1),
  activated_by: z.string().min(1),
});
export type MandateActivationRequest = z.infer<typeof mandateActivationRequestSchema>;

export const mandateRevocationRequestSchema = z.object({
  mandate_id: z.string().min(1),
  reason: z.string().default(""),
  revoked_by: z.string().min(1),
});
export type MandateRevocationRequest = z.infer<typeof mandateRevocationRequestSchema>;

export const mandateSuspensionRequestSchema = z.object({
  mandate_id: z.string().min(1),
  reason: z.string().default(""),
  suspended_by: z.string().min(1),
});
export type MandateSuspensionRequest = z.infer<typeof mandateSuspensionRequestSchema>;

export const mandateResumptionRequestSchema = z.object({
  mandate_id: z.string().min(1),
  resumed_by: z.string().min(1),
});
export type MandateResumptionRequest = z.infer<typeof mandateResumptionRequestSchema>;

export const budgetIncreaseRequestSchema = z.object({
  mandate_id: z.string().min(1),
  additional_cents: z.number().int().positive(),
  increased_by: z.string().min(1),
});
export type BudgetIncreaseRequest = z.infer<typeof budgetIncreaseRequestSchema>;

export const consumptionReportSchema = z.object({
  mandate_id: z.string().min(1),
  enforcement_request_id: z.string().min(1),
  amount_cents: z.number().int().positive(),
  description: z.string().default(""),
});
export type ConsumptionReport = z.infer<typeof consumptionReportSchema>;

export const ttlExtensionRequestSchema = z.object({
  mandate_id: z.string().min(1),
  additional_seconds: z.number().int().positive(),
  extended_by: z.string().min(1),
});
export type TTLExtensionRequest = z.infer<typeof ttlExtensionRequestSchema>;

export const delegationRequestSchema = z.object({
  parent_mandate_id: z.string().min(1),
  delegate_agent_id: z.string().min(1),
  scope_restriction: z.record(z.string(), z.unknown()).default({}),
  budget_cents: z.number().int().min(0),
  ttl_seconds: z.number().int().min(60),
  delegated_by: z.string().min(1),
});
export type DelegationRequest = z.infer<typeof delegationRequestSchema>;

export const activationResponseSchema = z.object({
  mandate_id: z.string(),
  status: z.literal("ACTIVE"),
  activated_at: z.string(),
  expires_at: z.string(),
});
export type ActivationResponse = z.infer<typeof activationResponseSchema>;

export const revocationResponseSchema = z.object({
  mandate_id: z.string(),
  status: z.literal("REVOKED"),
  reason: z.string(),
  revoked_at: z.string(),
});
export type RevocationResponse = z.infer<typeof revocationResponseSchema>;

export const suspensionResponseSchema = z.object({
  mandate_id: z.string(),
  status: z.literal("SUSPENDED"),
  reason: z.string(),
  suspended_at: z.string(),
});
export type SuspensionResponse = z.infer<typeof suspensionResponseSchema>;

export const resumptionResponseSchema = z.object({
  mandate_id: z.string(),
  status: z.literal("ACTIVE"),
  resumed_at: z.string(),
});
export type ResumptionResponse = z.infer<typeof resumptionResponseSchema>;

export const budgetIncreaseResponseSchema = z.object({
  mandate_id: z.string(),
  budget: budgetDetailSchema,
  additional_cents: z.number().int(),
  increased_by: z.string(),
});
export type BudgetIncreaseResponse = z.infer<typeof budgetIncreaseResponseSchema>;

export const consumptionResponseSchema = z.object({
  mandate_id: z.string(),
  enforcement_request_id: z.string(),
  amount_cents: z.number().int(),
  budget: budgetDetailSchema,
});
export type ConsumptionResponse = z.infer<typeof consumptionResponseSchema>;

export const ttlExtensionResponseSchema = z.object({
  mandate_id: z.string(),
  ttl_seconds: z.number().int(),
  expires_at: z.string(),
  additional_seconds: z.number().int(),
  extended_by: z.string(),
});
export type TTLExtensionResponse = z.infer<typeof ttlExtensionResponseSchema>;

export const delegationResponseSchema = z.object({
  mandate_id: z.string(),
  parent_mandate_id: z.string(),
  delegate_agent_id: z.string(),
  delegation_depth: z.number().int(),
  budget: budgetDetailSchema,
  scope: mandateScopeSchema,
  created_at: z.string(),
  expires_at: z.string(),
});
export type DelegationResponse = z.infer<typeof delegationResponseSchema>;

export const deleteResponseSchema = z.object({
  mandate_id: z.string(),
  deleted: z.boolean(),
});
export type DeleteResponse = z.infer<typeof deleteResponseSchema>;

export const mandateResponseSchema = z.object({
  mandate_id: z.string(),
  status: mandateStatusSchema,
  governance_profile: governanceProfileSchema,
  phase: phaseSchema,
  parties: partiesSchema,
  scope: mandateScopeSchema,
  requirements: mandateRequirementsSchema,
  budget: budgetDetailSchema,
  scope_checksum: z.string(),
  tool_permissions_hash: z.string(),
  platform_permissions_hash: z.string(),
  delegation_depth: z.number().int().min(0),
  parent_mandate_id: z.string().nullable(),
  created_at: z.string(),
  activated_at: z.string().nullable(),
  expires_at: z.string().nullable(),
  updated_at: z.string(),
});
export type MandateResponse = z.infer<typeof mandateResponseSchema>;

export const poaCredentialSchema = z.object({
  mandate_id: z.string(),
  subject: z.string(),
  governance_profile: governanceProfileSchema,
  phase: phaseSchema,
  jti: z.string().default(""),
  core_verbs: z.record(z.string(), z.unknown()).default({}),
  platform_permissions: z.record(z.string(), z.unknown()).default({}),
  allowed_paths: z.array(z.string()).default([]),
  denied_paths: z.array(z.string()).default([]),
  allowed_sectors: z.array(z.string()).default([]),
  allowed_regions: z.array(z.string()).default([]),
  allowed_transactions: z.array(z.string()).default([]),
  allowed_decisions: z.array(z.string()).default([]),
  approval_mode: approvalModeSchema.default("autonomous"),
  budget_total_cents: z.number().int().min(0).default(0),
  budget_remaining_cents: z.number().int().min(0).default(0),
  ttl_seconds: z.number().int().min(0).default(0),
  exp: z.string().nullable().default(null),
  nbf: z.string().nullable().default(null),
  scope_checksum: z.string().default(""),
  tool_permissions_hash: z.string().default(""),
  platform_permissions_hash: z.string().default(""),
  status: mandateStatusSchema.default("ACTIVE"),
  delegation_chain: z.array(delegationEntrySchema).default([]),
  session_limits: sessionLimitsSchema.default({
    max_tool_calls: null,
    max_session_duration_minutes: null,
    max_lines_per_commit: null,
  }),
});
export type PoACredential = z.infer<typeof poaCredentialSchema>;

export const validationErrorSchema = z.object({
  path: z.string().optional(),
  error: z.string(),
  code: z.string(),
});

export const ceilingViolationSchema = z.object({
  attribute: z.string(),
  requested: z.unknown(),
  ceiling: z.unknown(),
  profile: z.string(),
  code: z.string(),
});

export const consistencyErrorSchema = z.object({
  rule: z.string(),
  message: z.string(),
  code: z.string(),
});

export const validationResultResponseSchema = z.object({
  accepted: z.boolean(),
  schema_errors: z.array(validationErrorSchema),
  ceiling_violations: z.array(ceilingViolationSchema),
  consistency_errors: z.array(consistencyErrorSchema),
});
export type ValidationResultResponse = z.infer<typeof validationResultResponseSchema>;

export const creationResponseSchema = z.object({
  mandate_id: z.string(),
  status: z.literal("DRAFT"),
  governance_profile: governanceProfileSchema,
  scope_checksum: z.string(),
  tool_permissions_hash: z.string(),
  platform_permissions_hash: z.string(),
  created_at: z.string(),
  validation: validationResultResponseSchema,
});
export type CreationResponse = z.infer<typeof creationResponseSchema>;

export const paginatedResponseSchema = z.object({
  items: z.array(mandateResponseSchema),
  next_cursor: z.string().nullable(),
  total: z.number().int().min(0),
});
export type PaginatedResponse = z.infer<typeof paginatedResponseSchema>;

export const tariffSchema = z.enum(tariffValues);

export const tariffGateResultSchema = z.object({
  allowed: z.boolean(),
  availability: z.string(),
  reason: z.string().optional(),
});

export const poaPermissionEntrySchema = z.object({
  action: z.string(),
  resource: z.string().optional(),
  effect: z.string(),
});
export type PoaPermissionEntryZod = z.infer<typeof poaPermissionEntrySchema>;

export const poaMapSummarySchema = z.object({
  mandate_id: z.string(),
  subject: z.string(),
  governance_profile: governanceProfileSchema,
  status: mandateStatusSchema,
  permissions: z.array(poaPermissionEntrySchema).default([]),
  allowed_actions: z.array(z.string()).default([]),
  allowed_decisions: z.array(z.string()).default([]),
  allowedActions: z.array(z.string()).optional(),
  allowedDecisions: z.array(z.string()).optional(),
});
export type PoaMapSummaryZod = z.infer<typeof poaMapSummarySchema>;
