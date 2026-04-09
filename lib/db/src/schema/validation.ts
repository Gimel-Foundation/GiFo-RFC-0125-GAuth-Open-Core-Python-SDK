import { z } from "zod/v4";
import type { GovernanceProfile, ApprovalMode } from "./enums";
import { governanceProfileValues } from "./enums";
import { mandateCreationRequestSchema } from "./zod-schemas";
import { validateAgainstCeiling, getCeiling, type CeilingViolation } from "./ceilings";

export interface SchemaError {
  path?: string;
  error: string;
  code: string;
}

export interface ConsistencyError {
  rule: string;
  message: string;
  code: string;
}

export interface ValidationResult {
  accepted: boolean;
  schemaErrors: SchemaError[];
  ceilingViolations: CeilingViolation[];
  consistencyErrors: ConsistencyError[];
}

export function validateSchema(
  data: unknown,
): { parsed: z.infer<typeof mandateCreationRequestSchema> | null; errors: SchemaError[] } {
  const result = mandateCreationRequestSchema.safeParse(data);
  if (result.success) {
    return { parsed: result.data, errors: [] };
  }
  const errors: SchemaError[] = result.error.issues.map((issue) => ({
    path: issue.path.map(String).join("."),
    error: issue.message,
    code: "SCHEMA_TYPE_MISMATCH",
  }));
  return { parsed: null, errors };
}

export function validateCeilings(
  scope: Record<string, unknown>,
  requirements: Record<string, unknown>,
): CeilingViolation[] {
  const profileName = scope.governance_profile as string | undefined;
  if (
    !profileName ||
    !(governanceProfileValues as readonly string[]).includes(profileName)
  ) {
    return [
      {
        attribute: "governance_profile",
        requested: profileName ?? "",
        ceiling: "N/A",
        profile: "N/A",
        code: "PROFILE_NOT_FOUND",
      },
    ];
  }
  return validateAgainstCeiling(
    profileName as GovernanceProfile,
    scope,
    requirements,
  );
}

export function validateConsistency(
  scope: Record<string, unknown>,
  requirements: Record<string, unknown>,
  parties: Record<string, unknown>,
): ConsistencyError[] {
  const errors: ConsistencyError[] = [];

  const approvalMode = (requirements.approval_mode as string) ?? "autonomous";
  const approvalChain = (parties.approval_chain as string[]) ?? [];
  if (approvalMode === "four-eyes") {
    const unique = new Set(approvalChain);
    if (unique.size < 2) {
      errors.push({
        rule: "C-1",
        message:
          "four-eyes approval mode requires approval_chain with >= 2 distinct entries",
        code: "FOUR_EYES_MISSING_APPROVERS",
      });
    }
  }

  const allowedPaths = new Set((scope.allowed_paths as string[]) ?? []);
  const deniedPaths = new Set((scope.denied_paths as string[]) ?? []);
  const pathConflicts = [...allowedPaths].filter((p) => deniedPaths.has(p));
  if (pathConflicts.length > 0) {
    errors.push({
      rule: "C-2",
      message: `denied_paths and allowed_paths contain the same entries: ${JSON.stringify(pathConflicts.sort())}`,
      code: "PATH_CONFLICT",
    });
  }

  const budget = (requirements.budget as Record<string, unknown>) ?? {};
  const totalCents = (budget.total_cents as number) ?? 0;
  if (totalCents < 0) {
    errors.push({
      rule: "C-3",
      message: "Budget total_cents must be >= 0",
      code: "INVALID_BUDGET",
    });
  }

  const ttlSeconds = (requirements.ttl_seconds as number) ?? 0;
  if (ttlSeconds < 60) {
    errors.push({
      rule: "C-4",
      message: "TTL must be >= 60 seconds",
      code: "TTL_TOO_SHORT",
    });
  }

  const coreVerbs = (scope.core_verbs ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  for (const [verb, policy] of Object.entries(coreVerbs)) {
    if (
      typeof policy === "object" &&
      policy !== null &&
      policy.allowed === false &&
      policy.requires_approval === true
    ) {
      errors.push({
        rule: "C-5",
        message: `Verb '${verb}' is disallowed but also requires approval — contradictory`,
        code: "VERB_POLICY_CONTRADICTION",
      });
    }
  }

  const activeModules = (scope.active_modules ?? []) as string[];
  const knownModules = new Set([
    "file_ops",
    "git_ops",
    "shell",
    "database",
    "network",
    "secrets",
    "deployment",
    "monitoring",
    "delegation",
  ]);
  for (const mod of activeModules) {
    if (!knownModules.has(mod)) {
      errors.push({
        rule: "C-5b",
        message: `Unknown module '${mod}' in active_modules`,
        code: "UNKNOWN_MODULE",
      });
    }
  }

  const platformPerms = (scope.platform_permissions ?? {}) as Record<
    string,
    unknown
  >;
  const govProfile = scope.governance_profile as string | undefined;
  if (
    govProfile &&
    (governanceProfileValues as readonly string[]).includes(govProfile) &&
    Object.keys(platformPerms).length > 0
  ) {
    try {
      const ceiling = getCeiling(govProfile as GovernanceProfile);
      if (platformPerms.db_production === true && !ceiling.dbProduction) {
        errors.push({
          rule: "C-6",
          message: `db_production access requested but profile '${govProfile}' forbids it`,
          code: "PLATFORM_PROFILE_MISMATCH",
        });
      }
      if (platformPerms.db_migration === true && !ceiling.dbMigration) {
        errors.push({
          rule: "C-6",
          message: `db_migration access requested but profile '${govProfile}' forbids it`,
          code: "PLATFORM_PROFILE_MISMATCH",
        });
      }
    } catch {
      // profile lookup failed, skip C-6
    }
  }

  const allowedPaths2 = (scope.allowed_paths ?? []) as string[];
  const deniedPaths2 = (scope.denied_paths ?? []) as string[];
  if (allowedPaths2.length > 0 && deniedPaths2.length > 0) {
    for (const denied of deniedPaths2) {
      for (const allowed of allowedPaths2) {
        if (allowed.startsWith(denied) && allowed !== denied) {
          errors.push({
            rule: "C-6b",
            message: `Delegation scope conflict: allowed_path '${allowed}' is nested under denied_path '${denied}'`,
            code: "DELEGATION_SCOPE_CONFLICT",
          });
        }
      }
    }
  }

  return errors;
}

export interface DelegationNarrowingError {
  field: string;
  message: string;
  code: string;
}

export function validateDelegationScopeNarrowing(
  parentScope: Record<string, unknown>,
  childScope: Record<string, unknown>,
): DelegationNarrowingError[] {
  const errors: DelegationNarrowingError[] = [];

  const listFields = [
    "allowed_paths",
    "allowed_sectors",
    "allowed_regions",
    "allowed_transactions",
    "allowed_decisions",
  ];
  for (const field of listFields) {
    const parentList = new Set((parentScope[field] as string[] | undefined) ?? []);
    const childList = (childScope[field] as string[] | undefined) ?? [];
    if (parentList.size > 0) {
      for (const item of childList) {
        if (!parentList.has(item)) {
          errors.push({
            field,
            message: `Child scope widens '${field}': '${item}' not in parent`,
            code: "DELEGATION_SCOPE_WIDENING",
          });
        }
      }
    }
  }

  const parentVerbs = (parentScope.core_verbs ?? {}) as Record<string, Record<string, unknown>>;
  const childVerbs = (childScope.core_verbs ?? {}) as Record<string, Record<string, unknown>>;
  for (const [verb, childPolicy] of Object.entries(childVerbs)) {
    if (!(verb in parentVerbs)) {
      errors.push({
        field: "core_verbs",
        message: `Child scope adds verb '${verb}' not present in parent`,
        code: "DELEGATION_SCOPE_WIDENING",
      });
      continue;
    }
    const parentPolicy = parentVerbs[verb];
    if (
      typeof parentPolicy === "object" && parentPolicy !== null &&
      typeof childPolicy === "object" && childPolicy !== null
    ) {
      if (parentPolicy.allowed === false && childPolicy.allowed === true) {
        errors.push({
          field: "core_verbs",
          message: `Child scope re-enables disallowed verb '${verb}'`,
          code: "DELEGATION_SCOPE_WIDENING",
        });
      }
      if (parentPolicy.requires_approval === true && childPolicy.requires_approval === false) {
        errors.push({
          field: "core_verbs",
          message: `Child scope removes approval requirement for verb '${verb}'`,
          code: "DELEGATION_SCOPE_WIDENING",
        });
      }
    }
  }

  const parentPlatform = (parentScope.platform_permissions ?? {}) as Record<string, unknown>;
  const childPlatform = (childScope.platform_permissions ?? {}) as Record<string, unknown>;
  const boolPermissions = [
    "auto_deploy", "db_write", "db_migration", "db_production",
    "secrets_read", "secrets_create",
  ];
  for (const perm of boolPermissions) {
    if (parentPlatform[perm] === false && childPlatform[perm] === true) {
      errors.push({
        field: `platform_permissions.${perm}`,
        message: `Child scope enables '${perm}' which parent disallows`,
        code: "DELEGATION_SCOPE_WIDENING",
      });
    }
  }

  return errors;
}

export function validateMandate(data: unknown): ValidationResult {
  const result: ValidationResult = {
    accepted: true,
    schemaErrors: [],
    ceilingViolations: [],
    consistencyErrors: [],
  };

  const { errors: schemaErrors } = validateSchema(data);
  if (schemaErrors.length > 0) {
    result.schemaErrors = schemaErrors;
    result.accepted = false;
  }

  const obj = data as Record<string, unknown> | null;
  const scopeData = ((obj?.scope as Record<string, unknown>) ?? {});
  const reqData = ((obj?.requirements as Record<string, unknown>) ?? {});
  const partiesData = ((obj?.parties as Record<string, unknown>) ?? {});

  const ceilingViolations = validateCeilings(scopeData, reqData);
  if (ceilingViolations.length > 0) {
    result.ceilingViolations = ceilingViolations;
    result.accepted = false;
  }

  const consistencyErrors = validateConsistency(scopeData, reqData, partiesData);
  if (consistencyErrors.length > 0) {
    result.consistencyErrors = consistencyErrors;
    result.accepted = false;
  }

  return result;
}
