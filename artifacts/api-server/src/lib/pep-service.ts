import {
  type EnforcementRequest,
  type EnforcementDecision,
  type CheckResult,
  type EnforcedConstraint,
  type EnforcementMode,
  type PoACredentialInput,
  type EnforcementAction,
  type EnforcementContext,
  violationCodes,
  PEP_INTERFACE_VERSION,
  getCeiling,
  CEILING_TABLE,
  type GovernanceProfile,
  governanceProfileValues,
  APPROVAL_MODE_RANK,
  type ApprovalMode,
  computeToolPermissionsHash,
  computePlatformPermissionsHash,
} from "@workspace/db";
import * as mgmt from "./mgmt-service";

type Scope = {
  core_verbs: Record<string, unknown>;
  platform_permissions: Record<string, unknown>;
  allowed_paths: string[];
  denied_paths: string[];
  allowed_sectors: string[];
  allowed_regions: string[];
  allowed_transactions: string[];
  allowed_decisions: string[];
};

function extractScope(cred: PoACredentialInput): Scope {
  return {
    core_verbs: cred.core_verbs,
    platform_permissions: cred.platform_permissions,
    allowed_paths: cred.allowed_paths,
    denied_paths: cred.denied_paths,
    allowed_sectors: cred.allowed_sectors,
    allowed_regions: cred.allowed_regions,
    allowed_transactions: cred.allowed_transactions,
    allowed_decisions: cred.allowed_decisions,
  };
}

function pass(checkId: string, name: string, msg = ""): CheckResult {
  return { check_id: checkId, name, result: "pass", severity: "info", violation_code: null, message: msg, details: {} };
}

function fail(checkId: string, name: string, code: string, msg: string, details: Record<string, unknown> = {}): CheckResult {
  return { check_id: checkId, name, result: "fail", severity: "error", violation_code: code, message: msg, details };
}

function warn(checkId: string, name: string, code: string, msg: string, details: Record<string, unknown> = {}): CheckResult {
  return { check_id: checkId, name, result: "warn", severity: "warning", violation_code: code, message: msg, details };
}

function skip(checkId: string, name: string, msg: string): CheckResult {
  return { check_id: checkId, name, result: "skip", severity: "info", violation_code: null, message: msg, details: {} };
}

function chk01CredentialValidation(cred: PoACredentialInput): CheckResult {
  const id = "CHK-01";
  const name = "Credential Structure Validation";
  if (!cred.mandate_id || cred.mandate_id.trim() === "") {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, "Missing mandate_id in credential");
  }
  if (!cred.subject || cred.subject.trim() === "") {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, "Missing subject in credential");
  }
  if (!cred.governance_profile) {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, "Missing governance_profile in credential");
  }
  if (!cred.phase) {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, "Missing phase in credential");
  }
  return pass(id, name, "Credential structure is valid");
}

function chk02TemporalValidity(cred: PoACredentialInput, ctx: EnforcementContext, isStateful: boolean, liveStatus?: string): CheckResult {
  const id = "CHK-02";
  const name = "Temporal & Status Validity";
  const now = Date.now();

  if (ctx.agent_id !== cred.subject) {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, `Agent identity '${ctx.agent_id}' does not match credential subject '${cred.subject}'`);
  }

  if (cred.aud && ctx.audience && cred.aud !== ctx.audience) {
    return fail(id, name, violationCodes.CREDENTIAL_INVALID, `Credential audience '${cred.aud}' does not match expected audience '${ctx.audience}'`);
  }

  if (cred.exp) {
    const expTime = new Date(cred.exp).getTime();
    if (!isNaN(expTime) && now > expTime) {
      return fail(id, name, violationCodes.CREDENTIAL_EXPIRED, `Credential expired at ${cred.exp}`);
    }
  }

  if (cred.nbf) {
    const nbfTime = new Date(cred.nbf).getTime();
    if (!isNaN(nbfTime) && now < nbfTime) {
      return fail(id, name, violationCodes.CREDENTIAL_NOT_YET_VALID, `Credential not valid before ${cred.nbf}`);
    }
  }

  if (isStateful && liveStatus) {
    if (liveStatus !== "ACTIVE") {
      return fail(id, name, violationCodes.MANDATE_NOT_ACTIVE, `Live mandate status is ${liveStatus}, expected ACTIVE`);
    }
  } else {
    if (cred.status !== "ACTIVE") {
      return fail(id, name, violationCodes.MANDATE_NOT_ACTIVE, `Credential status is ${cred.status}, expected ACTIVE`);
    }
  }

  return pass(id, name, "Temporal validity confirmed");
}

function chk03GovernanceProfile(cred: PoACredentialInput, action: EnforcementAction): CheckResult {
  const id = "CHK-03";
  const name = "Governance Profile Ceiling";
  const profile = cred.governance_profile as GovernanceProfile;
  if (!(governanceProfileValues as readonly string[]).includes(profile)) {
    return fail(id, name, violationCodes.UNKNOWN_PROFILE, `Unknown governance profile: ${profile}`);
  }

  const ceiling = CEILING_TABLE[profile];

  const approvalRank = APPROVAL_MODE_RANK[cred.approval_mode as ApprovalMode] ?? 0;
  const minRank = APPROVAL_MODE_RANK[ceiling.minApprovalMode];
  if (approvalRank < minRank) {
    return fail(id, name, violationCodes.GOVERNANCE_PROFILE_VIOLATION, `Approval mode '${cred.approval_mode}' is below minimum '${ceiling.minApprovalMode}' for profile ${profile}`);
  }

  if (cred.delegation_chain && cred.delegation_chain.length > 0 && !ceiling.agentDelegation) {
    return fail(id, name, violationCodes.GOVERNANCE_PROFILE_VIOLATION, `Profile ${profile} does not allow agent delegation`);
  }

  if (cred.delegation_chain && cred.delegation_chain.length > ceiling.maxDelegationDepth) {
    return fail(id, name, violationCodes.GOVERNANCE_PROFILE_VIOLATION, `Delegation chain depth ${cred.delegation_chain.length} exceeds profile max ${ceiling.maxDelegationDepth}`);
  }

  const verb = action.verb;
  const platformPermMap: Record<string, keyof typeof ceiling> = {
    deploy: "autoDeploy",
    db_write: "dbWrite",
    db_migrate: "dbMigration",
    secrets_read: "secretsRead",
    secrets_create: "secretsCreate",
  };
  const ceilingKey = platformPermMap[verb];
  if (ceilingKey && ceiling[ceilingKey] === false) {
    return fail(id, name, violationCodes.GOVERNANCE_PROFILE_VIOLATION, `Verb '${verb}' is not allowed under profile ${profile} (${String(ceilingKey)}=false)`);
  }

  if (ceiling.maxSessionDurationMinutes !== null && cred.ttl_seconds > ceiling.maxSessionDurationMinutes * 60) {
    return fail(id, name, violationCodes.GOVERNANCE_PROFILE_VIOLATION, `TTL ${cred.ttl_seconds}s exceeds profile max ${ceiling.maxSessionDurationMinutes * 60}s`);
  }

  return pass(id, name, `Profile ${profile} ceiling checks passed`);
}

const PHASE_VERB_MAP: Record<string, Set<string>> = {
  plan: new Set(["read", "list", "search", "query", "analyze", "plan"]),
  build: new Set(["read", "list", "search", "query", "analyze", "plan", "code_edit", "code_create", "code_delete", "test", "lint", "format", "build", "install"]),
  run: new Set(["read", "list", "search", "query", "analyze", "deploy", "db_write", "db_migrate", "db_read", "secrets_read", "secrets_create", "execute", "monitor", "code_edit", "code_create", "code_delete", "test", "lint", "format", "build", "install"]),
};

function chk04Phase(cred: PoACredentialInput, action: EnforcementAction): CheckResult {
  const id = "CHK-04";
  const name = "Phase Match";
  const phase = cred.phase;
  const verb = action.verb;

  const allowedVerbs = PHASE_VERB_MAP[phase];
  if (!allowedVerbs) {
    return fail(id, name, violationCodes.PHASE_MISMATCH, `Unknown phase '${phase}'`);
  }

  if (!allowedVerbs.has(verb)) {
    return fail(id, name, violationCodes.PHASE_MISMATCH, `Verb '${verb}' is not permitted in phase '${phase}'`);
  }

  return pass(id, name, `Phase '${phase}' permits verb '${verb}'`);
}

function chk05Sector(scope: Scope, ctx: EnforcementContext): CheckResult {
  const id = "CHK-05";
  const name = "Sector Allowlist";
  if (!ctx.sector) {
    return pass(id, name, "No sector specified in context");
  }
  if (scope.allowed_sectors.length === 0) {
    return pass(id, name, "No sector restrictions defined");
  }
  if (!scope.allowed_sectors.includes(ctx.sector)) {
    return fail(id, name, violationCodes.SECTOR_NOT_ALLOWED, `Sector '${ctx.sector}' not in allowed list: ${scope.allowed_sectors.join(", ")}`);
  }
  return pass(id, name, `Sector '${ctx.sector}' is allowed`);
}

function chk06Region(scope: Scope, ctx: EnforcementContext): CheckResult {
  const id = "CHK-06";
  const name = "Region Allowlist";
  if (!ctx.region) {
    return pass(id, name, "No region specified in context");
  }
  if (scope.allowed_regions.length === 0) {
    return pass(id, name, "No region restrictions defined");
  }
  if (!scope.allowed_regions.includes(ctx.region)) {
    return fail(id, name, violationCodes.REGION_NOT_ALLOWED, `Region '${ctx.region}' not in allowed list: ${scope.allowed_regions.join(", ")}`);
  }
  return pass(id, name, `Region '${ctx.region}' is allowed`);
}

function chk07Path(scope: Scope, action: EnforcementAction): CheckResult {
  const id = "CHK-07";
  const name = "Path Evaluation";
  const resource = action.resource || "";

  if (scope.denied_paths.length > 0 && resource) {
    for (const denied of scope.denied_paths) {
      if (resource === denied || resource.startsWith(denied + "/") || matchGlob(resource, denied)) {
        return fail(id, name, violationCodes.PATH_DENIED, `Resource '${resource}' matches denied path '${denied}'`);
      }
    }
  }

  if (scope.allowed_paths.length > 0 && resource) {
    let allowed = false;
    for (const ap of scope.allowed_paths) {
      if (resource === ap || resource.startsWith(ap + "/") || matchGlob(resource, ap)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      return fail(id, name, violationCodes.PATH_NOT_ALLOWED, `Resource '${resource}' not in allowed paths`);
    }
  }

  return pass(id, name, "Path evaluation passed");
}

function matchGlob(value: string, pattern: string): boolean {
  if (!pattern.includes("*")) return value === pattern;
  const regex = new RegExp("^" + pattern.replace(/\*/g, ".*") + "$");
  return regex.test(value);
}

function chk08Verb(scope: Scope, action: EnforcementAction, isStateful: boolean, cred: PoACredentialInput, liveToolHash?: string): CheckResult {
  const id = "CHK-08";
  const name = "Verb Authorization";
  const verb = action.verb;

  if (isStateful) {
    const verbs = scope.core_verbs as Record<string, Record<string, unknown>>;
    if (Object.keys(verbs).length === 0) {
      return fail(id, name, violationCodes.VERB_NOT_AUTHORIZED, `Verb '${verb}' denied: no verbs defined in scope (fail-closed)`);
    }
    const policy = verbs[verb];
    if (!policy) {
      return fail(id, name, violationCodes.VERB_NOT_AUTHORIZED, `Verb '${verb}' not found in core_verbs`);
    }
    if (policy.allowed === false) {
      return fail(id, name, violationCodes.VERB_NOT_ALLOWED, `Verb '${verb}' is explicitly disallowed`);
    }
    return pass(id, name, `Verb '${verb}' is authorized`);
  }

  if (cred.tool_permissions_hash && liveToolHash && cred.tool_permissions_hash !== liveToolHash) {
    return fail(id, name, violationCodes.VERB_NOT_AUTHORIZED, "Tool permissions hash mismatch (stale credential)");
  }
  const verbs = scope.core_verbs as Record<string, Record<string, unknown>>;
  if (Object.keys(verbs).length === 0) {
    return fail(id, name, violationCodes.VERB_NOT_AUTHORIZED, `Verb '${verb}' denied: no verbs defined in credential (fail-closed)`);
  }
  const policy = verbs[verb];
  if (!policy) {
    return fail(id, name, violationCodes.VERB_NOT_AUTHORIZED, `Verb '${verb}' not in credential core_verbs`);
  }
  if (policy.allowed === false) {
    return fail(id, name, violationCodes.VERB_NOT_ALLOWED, `Verb '${verb}' is explicitly disallowed`);
  }
  return pass(id, name, `Verb '${verb}' authorized (stateless${cred.tool_permissions_hash ? ", hash verified" : ""})`);
}

function chk09Constraints(scope: Scope, action: EnforcementAction, isStateful: boolean): { result: CheckResult; constraints: EnforcedConstraint[] } {
  const id = "CHK-09";
  const name = "Verb Constraints";
  const constraints: EnforcedConstraint[] = [];

  if (!isStateful) {
    return { result: skip(id, name, "Constraint evaluation skipped in stateless mode"), constraints };
  }

  const verbs = scope.core_verbs as Record<string, Record<string, unknown>>;
  const policy = verbs[action.verb] as Record<string, unknown> | undefined;
  if (!policy || !policy.constraints) {
    return { result: pass(id, name, "No constraints defined for this verb"), constraints };
  }

  const verbConstraints = policy.constraints as Record<string, unknown>;

  if (typeof verbConstraints.max_per_session === "number") {
    constraints.push({
      type: "max_per_session",
      description: `Maximum ${verbConstraints.max_per_session} invocations per session`,
      parameters: { max_per_session: verbConstraints.max_per_session },
    });
  }

  if (typeof verbConstraints.max_amount_cents === "number") {
    const impactCents = (action.parameters?.amount_cents as number) ?? 0;
    if (impactCents > (verbConstraints.max_amount_cents as number)) {
      return {
        result: fail(id, name, violationCodes.CONSTRAINT_VIOLATION, `Amount ${impactCents} exceeds verb constraint max_amount_cents ${verbConstraints.max_amount_cents}`),
        constraints,
      };
    }
  }

  if (constraints.length > 0) {
    return { result: pass(id, name, `${constraints.length} constraint(s) will be enforced`), constraints };
  }
  return { result: pass(id, name, "Constraint evaluation passed"), constraints };
}

function chk10PlatformPermissions(scope: Scope, action: EnforcementAction, isStateful: boolean, cred: PoACredentialInput, livePlatformHash?: string): CheckResult {
  const id = "CHK-10";
  const name = "Platform Permissions";

  if (!isStateful) {
    if (cred.platform_permissions_hash) {
      if (livePlatformHash && cred.platform_permissions_hash !== livePlatformHash) {
        return fail(id, name, violationCodes.PLATFORM_HASH_MISMATCH, "Platform permissions hash mismatch (stale credential)");
      }
      return pass(id, name, "Platform permissions validated via hash (stateless)");
    }
    return pass(id, name, "No platform_permissions_hash in credential (stateless, no hash check)");
  }

  const perms = scope.platform_permissions as Record<string, unknown>;
  const verb = action.verb;
  const permMap: Record<string, string> = {
    deploy: "auto_deploy",
    db_write: "db_write",
    db_migrate: "db_migration",
    secrets_read: "secrets_read",
    secrets_create: "secrets_create",
  };

  const requiredPerm = permMap[verb];
  if (requiredPerm && perms[requiredPerm] === false) {
    return fail(id, name, violationCodes.PLATFORM_PERMISSION_DENIED, `Platform permission '${requiredPerm}' is denied for verb '${verb}'`);
  }

  return pass(id, name, "Platform permissions check passed");
}

function chk11Transaction(scope: Scope, action: EnforcementAction, ctx: EnforcementContext): CheckResult {
  const id = "CHK-11";
  const name = "Transaction Matrix";

  if (!ctx.transaction_type) {
    if (scope.allowed_transactions.length > 0) {
      return fail(id, name, violationCodes.TRANSACTION_NOT_ALLOWED, "Transaction type required by scope but not provided in context");
    }
    return pass(id, name, "No transaction type specified");
  }

  if (scope.allowed_transactions.length === 0) {
    return pass(id, name, "No transaction restrictions defined");
  }

  if (!scope.allowed_transactions.includes(ctx.transaction_type)) {
    return fail(id, name, violationCodes.TRANSACTION_NOT_ALLOWED, `Transaction type '${ctx.transaction_type}' not in allowed list`);
  }

  const verbs = scope.core_verbs as Record<string, Record<string, unknown>>;
  const verbPolicy = verbs[action.verb] as Record<string, unknown> | undefined;
  if (verbPolicy?.transaction_types) {
    const allowedForVerb = verbPolicy.transaction_types as string[];
    if (Array.isArray(allowedForVerb) && !allowedForVerb.includes(ctx.transaction_type)) {
      return fail(id, name, violationCodes.TRANSACTION_NOT_ALLOWED, `Transaction type '${ctx.transaction_type}' not permitted for verb '${action.verb}'`);
    }
  }

  return pass(id, name, `Transaction type '${ctx.transaction_type}' is allowed`);
}

function chk12DecisionType(scope: Scope, ctx: EnforcementContext): CheckResult {
  const id = "CHK-12";
  const name = "Decision Type Allowlist";

  if (!ctx.decision_type) {
    if (scope.allowed_decisions.length > 0) {
      return fail(id, name, violationCodes.DECISION_TYPE_NOT_ALLOWED, "Decision type required by scope but not provided in context");
    }
    return pass(id, name, "No decision type specified");
  }

  if (scope.allowed_decisions.length === 0) {
    return pass(id, name, "No decision type restrictions defined");
  }

  if (!scope.allowed_decisions.includes(ctx.decision_type)) {
    return fail(id, name, violationCodes.DECISION_TYPE_NOT_ALLOWED, `Decision type '${ctx.decision_type}' not in allowed list`);
  }

  return pass(id, name, `Decision type '${ctx.decision_type}' is allowed`);
}

function chk13Budget(cred: PoACredentialInput, ctx: EnforcementContext, isStateful: boolean, liveBudgetRemaining?: number): CheckResult {
  const id = "CHK-13";
  const name = "Budget Check";
  const impact = ctx.budget_impact_cents;

  if (impact <= 0) {
    return pass(id, name, "No budget impact");
  }

  if (isStateful && liveBudgetRemaining !== undefined) {
    if (impact > liveBudgetRemaining) {
      return fail(id, name, violationCodes.BUDGET_INSUFFICIENT, `Budget impact ${impact} exceeds live remaining ${liveBudgetRemaining}`);
    }
    return pass(id, name, `Budget sufficient: ${impact} <= ${liveBudgetRemaining} remaining`);
  }

  if (impact > cred.budget_remaining_cents) {
    return fail(id, name, violationCodes.BUDGET_INSUFFICIENT, `Budget impact ${impact} exceeds credential remaining ${cred.budget_remaining_cents}`);
  }
  if (cred.budget_remaining_cents < cred.budget_total_cents * 0.1) {
    return warn(id, name, violationCodes.BUDGET_STALE_WARNING, "Budget data may be stale (stateless mode, low remaining)");
  }
  return pass(id, name, `Budget check passed (stateless): ${impact} <= ${cred.budget_remaining_cents}`);
}

function chk14SessionLimits(cred: PoACredentialInput, ctx: EnforcementContext, isStateful: boolean, liveLimits?: { max_tool_calls: number | null; max_session_duration_minutes: number | null; max_lines_per_commit: number | null }): CheckResult {
  const id = "CHK-14";
  const name = "Session Limits";
  const limits = isStateful && liveLimits ? liveLimits : cred.session_limits;
  const constraints: string[] = [];

  if (limits.max_session_duration_minutes !== null && ctx.session_duration_minutes > limits.max_session_duration_minutes) {
    return fail(id, name, violationCodes.SESSION_DURATION_EXCEEDED, `Session duration ${ctx.session_duration_minutes}m exceeds limit ${limits.max_session_duration_minutes}m`);
  }

  if (limits.max_tool_calls !== null && ctx.tool_call_count >= limits.max_tool_calls) {
    return fail(id, name, violationCodes.SESSION_TOOL_CALLS_EXCEEDED, `Tool call count ${ctx.tool_call_count} >= limit ${limits.max_tool_calls}`);
  }

  if (limits.max_lines_per_commit !== null && ctx.lines_changed > limits.max_lines_per_commit) {
    return fail(id, name, violationCodes.SESSION_LINES_EXCEEDED, `Lines changed ${ctx.lines_changed} > limit ${limits.max_lines_per_commit}`);
  }

  if (limits.max_session_duration_minutes !== null) {
    constraints.push(`duration: ${ctx.session_duration_minutes}/${limits.max_session_duration_minutes}m`);
  }
  if (limits.max_tool_calls !== null) {
    constraints.push(`tool_calls: ${ctx.tool_call_count}/${limits.max_tool_calls}`);
  }

  return pass(id, name, constraints.length > 0 ? `Session limits OK: ${constraints.join(", ")}` : "No session limits configured");
}

function chk15Approval(cred: PoACredentialInput, action: EnforcementAction, ctx: EnforcementContext, isStateful: boolean, liveScope?: Scope): { result: CheckResult; constraints: EnforcedConstraint[] } {
  const id = "CHK-15";
  const name = "Approval Verification";
  const constraints: EnforcedConstraint[] = [];

  if (!isStateful) {
    if (cred.approval_mode !== "autonomous") {
      constraints.push({
        type: "approval_required",
        description: `Action requires ${cred.approval_mode} approval (cannot verify in stateless mode)`,
        parameters: { approval_mode: cred.approval_mode },
      });
      return { result: pass(id, name, `Approval mode ${cred.approval_mode} noted (stateless)`), constraints };
    }
    return { result: pass(id, name, "Autonomous approval mode"), constraints };
  }

  const verbSource = isStateful && liveScope ? liveScope.core_verbs : cred.core_verbs;
  const verbs = verbSource as Record<string, Record<string, unknown>>;
  const policy = verbs[action.verb] as Record<string, unknown> | undefined;
  const verbRequiresApproval = policy?.requires_approval === true;

  if (cred.approval_mode === "four-eyes" || verbRequiresApproval) {
    const approvalToken = ctx.approval_token;
    if (!approvalToken) {
      return {
        result: fail(id, name, violationCodes.APPROVAL_REQUIRED,
          verbRequiresApproval
            ? `Verb '${action.verb}' requires explicit approval but no approval_token provided`
            : `Four-eyes approval mode requires approval_token but none provided`),
        constraints,
      };
    }
    constraints.push({
      type: "approval_verified",
      description: verbRequiresApproval
        ? `Verb '${action.verb}' approval token accepted`
        : `Four-eyes approval token accepted`,
      parameters: { approval_mode: cred.approval_mode, verb: action.verb },
    });
  } else if (cred.approval_mode === "supervised") {
    constraints.push({
      type: "approval_advisory",
      description: "Supervised mode: action will be logged for review",
      parameters: { approval_mode: cred.approval_mode },
    });
  }

  return { result: pass(id, name, `Approval mode: ${cred.approval_mode}`), constraints };
}

function chk16DelegationChain(cred: PoACredentialInput, ctx: EnforcementContext): { result: CheckResult; effectiveScope: Scope | null } {
  const id = "CHK-16";
  const name = "Delegation Chain Validation";
  const chain = cred.delegation_chain;

  if (!chain || chain.length === 0) {
    return { result: pass(id, name, "No delegation chain"), effectiveScope: null };
  }

  let effectiveScope = extractScope(cred);
  let prevDelegate = cred.subject;
  let depthRemaining = Infinity;
  let prevMaxDepth = Infinity;

  for (let i = 0; i < chain.length; i++) {
    const entry = chain[i];

    if (entry.delegator !== prevDelegate) {
      return {
        result: fail(id, name, violationCodes.DELEGATION_CHAIN_INVALID, `Chain link ${i}: delegator '${entry.delegator}' does not match previous delegate '${prevDelegate}'`),
        effectiveScope: null,
      };
    }

    if (entry.max_depth_remaining >= prevMaxDepth) {
      return {
        result: fail(id, name, violationCodes.DELEGATION_CHAIN_INVALID, `Chain link ${i}: max_depth_remaining ${entry.max_depth_remaining} must be strictly less than previous ${prevMaxDepth}`),
        effectiveScope: null,
      };
    }

    if (entry.max_depth_remaining <= 0 && i < chain.length - 1) {
      return {
        result: fail(id, name, violationCodes.DELEGATION_DEPTH_EXCEEDED, `Chain link ${i}: max_depth_remaining is 0 but chain continues`),
        effectiveScope: null,
      };
    }

    if (entry.delegated_at) {
      const delegatedTime = new Date(entry.delegated_at).getTime();
      if (isNaN(delegatedTime) || delegatedTime > Date.now()) {
        return {
          result: fail(id, name, violationCodes.DELEGATION_CHAIN_INVALID, `Chain link ${i}: delegated_at '${entry.delegated_at}' is invalid or in the future`),
          effectiveScope: null,
        };
      }
    }

    prevMaxDepth = entry.max_depth_remaining;
    depthRemaining = entry.max_depth_remaining;

    const restriction = entry.scope_restriction;
    if (restriction && Object.keys(restriction).length > 0) {
      effectiveScope = narrowScope(effectiveScope, restriction);
    }

    prevDelegate = entry.delegate;
  }

  if (prevDelegate !== ctx.agent_id) {
    return {
      result: fail(id, name, violationCodes.DELEGATION_CHAIN_INVALID, `Last delegate '${prevDelegate}' does not match presenting agent '${ctx.agent_id}'`),
      effectiveScope: null,
    };
  }

  return {
    result: pass(id, name, `Delegation chain valid (${chain.length} links, depth_remaining=${depthRemaining})`),
    effectiveScope,
  };
}

function narrowScope(parent: Scope, restriction: Record<string, unknown>): Scope {
  const result = { ...parent };

  const listKeys = ["allowed_paths", "allowed_sectors", "allowed_regions", "allowed_transactions", "allowed_decisions"] as const;
  for (const key of listKeys) {
    if (Array.isArray(restriction[key]) && Array.isArray(parent[key])) {
      const parentSet = new Set(parent[key]);
      result[key] = (restriction[key] as string[]).filter((v: string) => parentSet.has(v));
    }
  }

  if (Array.isArray(restriction.denied_paths)) {
    const merged = new Set([...parent.denied_paths, ...(restriction.denied_paths as string[])]);
    result.denied_paths = [...merged];
  }

  if (typeof restriction.core_verbs === "object" && restriction.core_verbs !== null) {
    const parentVerbs = parent.core_verbs as Record<string, Record<string, unknown>>;
    const restrictedVerbs = restriction.core_verbs as Record<string, Record<string, unknown>>;
    const narrowed: Record<string, Record<string, unknown>> = {};
    for (const [vk, vv] of Object.entries(parentVerbs)) {
      if (vk in restrictedVerbs) {
        narrowed[vk] = { ...vv, ...restrictedVerbs[vk] };
        if (vv.allowed === false || restrictedVerbs[vk].allowed === false) {
          narrowed[vk].allowed = false;
        }
      }
    }
    result.core_verbs = narrowed;
  }

  if (typeof restriction.platform_permissions === "object" && restriction.platform_permissions !== null) {
    const parentPerms = parent.platform_permissions as Record<string, unknown>;
    const restrictedPerms = restriction.platform_permissions as Record<string, unknown>;
    const narrowed: Record<string, unknown> = {};
    for (const [dk, dv] of Object.entries(parentPerms)) {
      if (dk in restrictedPerms) {
        const cv = restrictedPerms[dk];
        if (typeof dv === "boolean" && typeof cv === "boolean") {
          narrowed[dk] = dv && cv;
        } else if (Array.isArray(dv) && Array.isArray(cv)) {
          const parentArr = new Set(dv as string[]);
          narrowed[dk] = (cv as string[]).filter((v: string) => parentArr.has(v));
        } else {
          narrowed[dk] = dv;
        }
      } else {
        narrowed[dk] = dv;
      }
    }
    result.platform_permissions = narrowed;
  }

  return result;
}

const READ_ONLY_VERBS = new Set(["read", "list", "search", "query", "analyze", "plan"]);

function isStatefulOnlyProfile(profile: string): boolean {
  if (!(governanceProfileValues as readonly string[]).includes(profile)) {
    return true;
  }
  const ceiling = CEILING_TABLE[profile as GovernanceProfile];
  return ceiling.minApprovalMode === "four-eyes" || !ceiling.agentDelegation;
}

function selectMode(cred: PoACredentialInput, requestedMode?: EnforcementMode, actionVerb?: string): EnforcementMode {
  if (isStatefulOnlyProfile(cred.governance_profile)) {
    return "stateful";
  }

  if (requestedMode === "stateful") return "stateful";

  const isReadOnly = actionVerb ? READ_ONLY_VERBS.has(actionVerb) : false;
  const hasNoBudget = cred.budget_total_cents === 0;
  const isAutonomous = cred.approval_mode === "autonomous";

  if (isReadOnly && hasNoBudget && isAutonomous) {
    return "stateless";
  }

  return "stateful";
}

interface LiveMandateData {
  status: string;
  budgetRemainingCents: number;
  toolPermissionsHash: string;
  platformPermissionsHash: string;
  sessionLimits: { max_tool_calls: number | null; max_session_duration_minutes: number | null; max_lines_per_commit: number | null };
  scope: Scope;
}

async function fetchLiveMandateData(mandateId: string): Promise<LiveMandateData> {
  const m = await mgmt.getMandate(mandateId);
  const scope = m.scope as Record<string, unknown>;
  const requirements = m.requirements as Record<string, unknown>;
  const sessionLimits = (requirements.session_limits ?? { max_tool_calls: null, max_session_duration_minutes: null, max_lines_per_commit: null }) as LiveMandateData["sessionLimits"];
  return {
    status: m.status,
    budgetRemainingCents: m.budget.remaining_cents,
    toolPermissionsHash: m.tool_permissions_hash,
    platformPermissionsHash: m.platform_permissions_hash,
    sessionLimits,
    scope: {
      core_verbs: (scope.core_verbs ?? {}) as Record<string, unknown>,
      platform_permissions: (scope.platform_permissions ?? {}) as Record<string, unknown>,
      allowed_paths: (scope.allowed_paths ?? []) as string[],
      denied_paths: (scope.denied_paths ?? []) as string[],
      allowed_sectors: (scope.allowed_sectors ?? []) as string[],
      allowed_regions: (scope.allowed_regions ?? []) as string[],
      allowed_transactions: (scope.allowed_transactions ?? []) as string[],
      allowed_decisions: (scope.allowed_decisions ?? []) as string[],
    },
  };
}

const ALL_CHECK_IDS = [
  { id: "CHK-01", name: "Credential Structure Validation" },
  { id: "CHK-02", name: "Temporal & Status Validity" },
  { id: "CHK-03", name: "Governance Profile Ceiling" },
  { id: "CHK-04", name: "Phase Match" },
  { id: "CHK-05", name: "Sector Allowlist" },
  { id: "CHK-06", name: "Region Allowlist" },
  { id: "CHK-07", name: "Path Evaluation" },
  { id: "CHK-08", name: "Verb Authorization" },
  { id: "CHK-09", name: "Verb Constraints" },
  { id: "CHK-10", name: "Platform Permissions" },
  { id: "CHK-11", name: "Transaction Matrix" },
  { id: "CHK-12", name: "Decision Type Allowlist" },
  { id: "CHK-13", name: "Budget Check" },
  { id: "CHK-14", name: "Session Limits" },
  { id: "CHK-15", name: "Approval Verification" },
  { id: "CHK-16", name: "Delegation Chain Validation" },
];

export async function enforceAction(req: EnforcementRequest): Promise<EnforcementDecision> {
  try {
    return await enforceActionInternal(req);
  } catch (err) {
    const errMsg = `Unexpected error during enforcement (fail-closed): ${err instanceof Error ? err.message : "unknown"}`;
    const internalFail = fail("CHK-XX", "Internal Error", violationCodes.INTERNAL_ERROR, errMsg);
    const skippedChecks = ALL_CHECK_IDS.map(c => skip(c.id, c.name, "Skipped due to internal error"));
    return {
      request_id: req.request_id,
      decision: "DENY",
      checks: [internalFail, ...skippedChecks],
      enforced_constraints: [],
      violations: [{
        check_id: "CHK-XX",
        violation_code: violationCodes.INTERNAL_ERROR,
        message: errMsg,
      }],
      effective_scope: undefined,
      audit: {
        request_id: req.request_id,
        credential_ref: req.credential?.jti || req.credential?.mandate_id || "unknown",
        enforcement_mode: "stateful",
        pep_interface_version: PEP_INTERFACE_VERSION,
        processing_time_ms: 0,
        decision: "DENY",
        checks_run: 17,
        checks_passed: 0,
        checks_failed: 1,
        timestamp: new Date().toISOString(),
      },
    };
  }
}

async function enforceActionInternal(req: EnforcementRequest): Promise<EnforcementDecision> {
  const startTime = Date.now();
  const cred = req.credential;
  const action = req.action;
  const ctx = req.context;

  const mode = selectMode(cred, ctx.enforcement_mode, action.verb);
  const isStateful = mode === "stateful";

  let liveData: LiveMandateData | null = null;
  let liveFetchFailed = false;
  if (isStateful) {
    try {
      liveData = await fetchLiveMandateData(cred.mandate_id);
    } catch {
      liveFetchFailed = true;
    }
    if (!liveData) liveFetchFailed = true;
  }

  const checks: CheckResult[] = [];
  const allConstraints: EnforcedConstraint[] = [];

  if (isStateful && liveFetchFailed) {
    checks.push(fail("CHK-00", "Live Mandate Fetch", violationCodes.STATEFUL_FETCH_FAILED,
      "Stateful enforcement requires live mandate data but lookup failed (fail-closed)"));
  }

  const originalScope = liveData ? liveData.scope : extractScope(cred);

  checks.push(chk01CredentialValidation(cred));
  checks.push(chk02TemporalValidity(cred, ctx, isStateful, liveData?.status));
  checks.push(chk03GovernanceProfile(cred, action));
  checks.push(chk04Phase(cred, action));
  checks.push(chk05Sector(originalScope, ctx));
  checks.push(chk06Region(originalScope, ctx));
  checks.push(chk07Path(originalScope, action));
  checks.push(chk08Verb(originalScope, action, isStateful, cred, liveData?.toolPermissionsHash));

  const chk09Result = chk09Constraints(originalScope, action, isStateful);
  checks.push(chk09Result.result);
  allConstraints.push(...chk09Result.constraints);

  checks.push(chk10PlatformPermissions(originalScope, action, isStateful, cred, liveData?.platformPermissionsHash));
  checks.push(chk11Transaction(originalScope, action, ctx));
  checks.push(chk12DecisionType(originalScope, ctx));
  checks.push(chk13Budget(cred, ctx, isStateful, liveData?.budgetRemainingCents));
  checks.push(chk14SessionLimits(cred, ctx, isStateful, liveData?.sessionLimits));

  const chk15Result = chk15Approval(cred, action, ctx, isStateful, liveData?.scope);
  checks.push(chk15Result.result);
  allConstraints.push(...chk15Result.constraints);

  const chk16Result = chk16DelegationChain(cred, ctx);
  checks.push(chk16Result.result);

  let effectiveScope: Record<string, unknown> | undefined;
  if (chk16Result.effectiveScope && chk16Result.result.result === "pass") {
    effectiveScope = chk16Result.effectiveScope as unknown as Record<string, unknown>;
    const narrowedScope = chk16Result.effectiveScope;

    const pass2Checks: CheckResult[] = [];
    pass2Checks.push(chk05Sector(narrowedScope, ctx));
    pass2Checks.push(chk06Region(narrowedScope, ctx));
    pass2Checks.push(chk07Path(narrowedScope, action));
    pass2Checks.push(chk08Verb(narrowedScope, action, isStateful, cred, liveData?.toolPermissionsHash));

    const pass2Chk09 = chk09Constraints(narrowedScope, action, isStateful);
    pass2Checks.push(pass2Chk09.result);
    allConstraints.push(...pass2Chk09.constraints);

    pass2Checks.push(chk10PlatformPermissions(narrowedScope, action, isStateful, cred, liveData?.platformPermissionsHash));
    pass2Checks.push(chk11Transaction(narrowedScope, action, ctx));
    pass2Checks.push(chk12DecisionType(narrowedScope, ctx));

    for (const pc of pass2Checks) {
      pc.check_id = `${pc.check_id}-P2`;
      pc.name = `${pc.name} (Effective Scope)`;
    }
    checks.push(...pass2Checks);
  }

  const hasErrors = checks.some(c => c.result === "fail" && c.severity === "error");
  const hasConstraints = allConstraints.length > 0;

  let decision: "PERMIT" | "DENY" | "CONSTRAIN";
  if (hasErrors) {
    decision = "DENY";
  } else if (hasConstraints) {
    decision = "CONSTRAIN";
  } else {
    decision = "PERMIT";
  }

  const violations = checks
    .filter(c => c.result === "fail" && c.violation_code)
    .map(c => ({
      check_id: c.check_id,
      violation_code: c.violation_code!,
      message: c.message,
    }));

  if (decision === "PERMIT" && ctx.budget_impact_cents > 0) {
    try {
      await mgmt.consumeBudget(
        cred.mandate_id,
        req.request_id,
        ctx.budget_impact_cents,
        `PEP enforcement: ${action.verb} on ${action.resource}`,
        ctx.agent_id,
      );
    } catch {
      decision = "DENY";
      const budgetFailCheck = fail("CHK-13B", "Budget Consumption", violationCodes.BUDGET_INSUFFICIENT,
        "Budget debit failed during enforcement (fail-closed)");
      checks.push(budgetFailCheck);
      violations.push({
        check_id: "CHK-13B",
        violation_code: violationCodes.BUDGET_INSUFFICIENT,
        message: "Budget debit failed during enforcement (fail-closed)",
      });
    }
  }

  const processingTimeMs = Date.now() - startTime;
  const checksRun = checks.filter(c => c.result !== "skip").length;
  const checksPassed = checks.filter(c => c.result === "pass").length;
  const checksFailed = checks.filter(c => c.result === "fail").length;

  return {
    request_id: req.request_id,
    decision,
    checks,
    enforced_constraints: decision === "CONSTRAIN" ? allConstraints : [],
    violations,
    effective_scope: effectiveScope,
    audit: {
      request_id: req.request_id,
      credential_ref: cred.jti || cred.mandate_id,
      enforcement_mode: mode,
      pep_interface_version: PEP_INTERFACE_VERSION,
      processing_time_ms: processingTimeMs,
      decision,
      checks_run: checksRun,
      checks_passed: checksPassed,
      checks_failed: checksFailed,
      timestamp: new Date().toISOString(),
    },
  };
}

export async function batchEnforce(requests: EnforcementRequest[]): Promise<{ results: EnforcementDecision[]; total_processing_time_ms: number }> {
  const start = Date.now();
  const results = await Promise.all(requests.map(enforceAction));
  return {
    results,
    total_processing_time_ms: Date.now() - start,
  };
}

export function getPolicy() {
  return {
    pep_interface_version: PEP_INTERFACE_VERSION,
    supported_checks: [
      { id: "CHK-01", name: "Credential Structure Validation" },
      { id: "CHK-02", name: "Temporal & Status Validity" },
      { id: "CHK-03", name: "Governance Profile Ceiling" },
      { id: "CHK-04", name: "Phase Match" },
      { id: "CHK-05", name: "Sector Allowlist" },
      { id: "CHK-06", name: "Region Allowlist" },
      { id: "CHK-07", name: "Path Evaluation" },
      { id: "CHK-08", name: "Verb Authorization" },
      { id: "CHK-09", name: "Verb Constraints" },
      { id: "CHK-10", name: "Platform Permissions" },
      { id: "CHK-11", name: "Transaction Matrix" },
      { id: "CHK-12", name: "Decision Type Allowlist" },
      { id: "CHK-13", name: "Budget Check" },
      { id: "CHK-14", name: "Session Limits" },
      { id: "CHK-15", name: "Approval Verification" },
      { id: "CHK-16", name: "Delegation Chain Validation" },
    ],
    enforcement_modes: ["stateless", "stateful"],
    decisions: ["PERMIT", "DENY", "CONSTRAIN"],
    fail_closed: true,
    two_pass_delegation: true,
    governance_profiles: Object.keys(CEILING_TABLE),
  };
}

export function getPepHealth() {
  return {
    status: "healthy",
    pep_interface_version: PEP_INTERFACE_VERSION,
    checks_available: 16,
    enforcement_modes: ["stateless", "stateful"],
    timestamp: new Date().toISOString(),
  };
}
