import type { GovernanceProfile, ApprovalMode, ShellMode } from "./enums";
import { APPROVAL_MODE_RANK } from "./enums";

export interface CeilingDefinition {
  readonly deploymentTargets: ReadonlySet<string>;
  readonly autoDeploy: boolean;
  readonly dbWrite: boolean;
  readonly dbMigration: boolean;
  readonly dbProduction: boolean;
  readonly shellMode: ShellMode;
  readonly packagesAuditedOnly: boolean;
  readonly secretsRead: boolean;
  readonly secretsCreate: boolean;
  readonly agentDelegation: boolean;
  readonly maxDelegationDepth: number;
  readonly minApprovalMode: ApprovalMode;
  readonly maxSessionDurationMinutes: number | null;
  readonly maxToolCalls: number | null;
  readonly maxLinesPerCommit: number | null;
  readonly description: string;
  readonly registrationContext: string;
}

export const CEILING_TABLE: Readonly<
  Record<GovernanceProfile, CeilingDefinition>
> = {
  minimal: {
    deploymentTargets: new Set(["dev", "staging", "prod"]),
    autoDeploy: true,
    dbWrite: true,
    dbMigration: true,
    dbProduction: true,
    shellMode: "any",
    packagesAuditedOnly: false,
    secretsRead: true,
    secretsCreate: true,
    agentDelegation: true,
    maxDelegationDepth: 99,
    minApprovalMode: "autonomous",
    maxSessionDurationMinutes: null,
    maxToolCalls: null,
    maxLinesPerCommit: null,
    description: "Least restrictive. Maximum autonomy.",
    registrationContext: "Prototyping, personal projects",
  },
  standard: {
    deploymentTargets: new Set(["dev", "staging"]),
    autoDeploy: false,
    dbWrite: true,
    dbMigration: false,
    dbProduction: false,
    shellMode: "denylist",
    packagesAuditedOnly: false,
    secretsRead: true,
    secretsCreate: false,
    agentDelegation: true,
    maxDelegationDepth: 1,
    minApprovalMode: "supervised",
    maxSessionDurationMinutes: 240,
    maxToolCalls: 500,
    maxLinesPerCommit: 500,
    description: "Balanced restrictions. Supervised approval.",
    registrationContext: "Small teams, general development",
  },
  strict: {
    deploymentTargets: new Set(["staging"]),
    autoDeploy: false,
    dbWrite: true,
    dbMigration: false,
    dbProduction: false,
    shellMode: "allowlist",
    packagesAuditedOnly: true,
    secretsRead: true,
    secretsCreate: false,
    agentDelegation: true,
    maxDelegationDepth: 1,
    minApprovalMode: "supervised",
    maxSessionDurationMinutes: 120,
    maxToolCalls: 200,
    maxLinesPerCommit: 200,
    description: "Restrictive. Audited packages, allowlist shell.",
    registrationContext: "Regulated industries",
  },
  enterprise: {
    deploymentTargets: new Set(["staging"]),
    autoDeploy: false,
    dbWrite: false,
    dbMigration: false,
    dbProduction: false,
    shellMode: "allowlist",
    packagesAuditedOnly: true,
    secretsRead: false,
    secretsCreate: false,
    agentDelegation: false,
    maxDelegationDepth: 0,
    minApprovalMode: "supervised",
    maxSessionDurationMinutes: 60,
    maxToolCalls: 100,
    maxLinesPerCommit: 100,
    description: "Highly restrictive. No delegation, no secrets access.",
    registrationContext: "Enterprise organizations",
  },
  behoerde: {
    deploymentTargets: new Set(["staging"]),
    autoDeploy: false,
    dbWrite: false,
    dbMigration: false,
    dbProduction: false,
    shellMode: "allowlist",
    packagesAuditedOnly: true,
    secretsRead: false,
    secretsCreate: false,
    agentDelegation: false,
    maxDelegationDepth: 0,
    minApprovalMode: "four-eyes",
    maxSessionDurationMinutes: 30,
    maxToolCalls: 100,
    maxLinesPerCommit: 100,
    description: "Most restrictive. Four-eyes approval, 30-minute sessions.",
    registrationContext: "Public sector / government",
  },
};

export function getCeiling(profile: GovernanceProfile): CeilingDefinition {
  const ceiling = CEILING_TABLE[profile];
  if (!ceiling) {
    throw new Error(`Unknown governance profile: ${profile}`);
  }
  return ceiling;
}

export function getProfileInfo(profile: GovernanceProfile) {
  const ceiling = getCeiling(profile);
  return {
    name: profile,
    description: ceiling.description,
    registrationContext: ceiling.registrationContext,
  };
}

export function listProfiles() {
  return (
    Object.keys(CEILING_TABLE) as GovernanceProfile[]
  ).map(getProfileInfo);
}

export interface CeilingViolation {
  attribute: string;
  requested: unknown;
  ceiling: unknown;
  profile: string;
  code: string;
}

export function validateAgainstCeiling(
  profile: GovernanceProfile,
  scope: Record<string, unknown>,
  requirements: Record<string, unknown>,
): CeilingViolation[] {
  const ceiling = getCeiling(profile);
  const violations: CeilingViolation[] = [];
  const platform = (scope.platform_permissions ?? {}) as Record<string, unknown>;

  const boolChecks: Array<{
    key: string;
    ceilVal: boolean;
    invert?: boolean;
  }> = [
    { key: "auto_deploy", ceilVal: ceiling.autoDeploy },
    { key: "db_write", ceilVal: ceiling.dbWrite },
    { key: "db_migration", ceilVal: ceiling.dbMigration },
    { key: "db_production", ceilVal: ceiling.dbProduction },
    { key: "secrets_read", ceilVal: ceiling.secretsRead },
    { key: "secrets_create", ceilVal: ceiling.secretsCreate },
  ];

  for (const { key, ceilVal } of boolChecks) {
    if (platform[key] === true && !ceilVal) {
      violations.push({
        attribute: key,
        requested: true,
        ceiling: false,
        profile: ceiling.description,
        code: "CEILING_VIOLATION",
      });
    }
  }

  if (platform.packages_audited_only === false && ceiling.packagesAuditedOnly) {
    violations.push({
      attribute: "packages_audited_only",
      requested: false,
      ceiling: true,
      profile: ceiling.description,
      code: "CEILING_VIOLATION",
    });
  }

  const reqTargets = new Set(
    (platform.deployment_targets as string[] | undefined) ?? [],
  );
  if (reqTargets.size > 0) {
    for (const t of reqTargets) {
      if (!ceiling.deploymentTargets.has(t)) {
        violations.push({
          attribute: "deployment_targets",
          requested: [...reqTargets].sort(),
          ceiling: [...ceiling.deploymentTargets].sort(),
          profile: ceiling.description,
          code: "CEILING_VIOLATION",
        });
        break;
      }
    }
  }

  const shellRank: Record<string, number> = {
    any: 0,
    denylist: 1,
    allowlist: 2,
  };
  const reqShell = (platform.shell_mode as string) ?? "any";
  if ((shellRank[reqShell] ?? 0) < shellRank[ceiling.shellMode]) {
    violations.push({
      attribute: "shell_mode",
      requested: reqShell,
      ceiling: ceiling.shellMode,
      profile: ceiling.description,
      code: "CEILING_VIOLATION",
    });
  }

  const approval = (requirements.approval_mode as string) ?? "autonomous";
  const reqRank = APPROVAL_MODE_RANK[approval as ApprovalMode] ?? 0;
  const ceilRank = APPROVAL_MODE_RANK[ceiling.minApprovalMode];
  if (reqRank < ceilRank) {
    violations.push({
      attribute: "min_approval_mode",
      requested: approval,
      ceiling: ceiling.minApprovalMode,
      profile: ceiling.description,
      code: "CEILING_VIOLATION",
    });
  }

  const session = (requirements.session_limits ?? {}) as Record<string, unknown>;

  if (ceiling.maxSessionDurationMinutes !== null) {
    const reqDur = session.max_session_duration_minutes as number | undefined;
    if (reqDur !== undefined && reqDur !== null && reqDur > ceiling.maxSessionDurationMinutes) {
      violations.push({
        attribute: "max_session_duration_minutes",
        requested: reqDur,
        ceiling: ceiling.maxSessionDurationMinutes,
        profile: ceiling.description,
        code: "CEILING_VIOLATION",
      });
    }
  }

  if (ceiling.maxToolCalls !== null) {
    const reqTc = session.max_tool_calls as number | undefined;
    if (reqTc !== undefined && reqTc !== null && reqTc > ceiling.maxToolCalls) {
      violations.push({
        attribute: "max_tool_calls",
        requested: reqTc,
        ceiling: ceiling.maxToolCalls,
        profile: ceiling.description,
        code: "CEILING_VIOLATION",
      });
    }
  }

  if (ceiling.maxLinesPerCommit !== null) {
    const reqLpc = session.max_lines_per_commit as number | undefined;
    if (reqLpc !== undefined && reqLpc !== null && reqLpc > ceiling.maxLinesPerCommit) {
      violations.push({
        attribute: "max_lines_per_commit",
        requested: reqLpc,
        ceiling: ceiling.maxLinesPerCommit,
        profile: ceiling.description,
        code: "CEILING_VIOLATION",
      });
    }
  }

  if (!ceiling.agentDelegation) {
    const coreVerbs = (scope.core_verbs ?? {}) as Record<
      string,
      Record<string, unknown>
    >;
    for (const verbPolicy of Object.values(coreVerbs)) {
      if (
        typeof verbPolicy === "object" &&
        verbPolicy !== null
      ) {
        const constraints = (verbPolicy.constraints ?? {}) as Record<
          string,
          unknown
        >;
        if (
          typeof constraints.max_delegation_depth === "number" &&
          constraints.max_delegation_depth > 0
        ) {
          violations.push({
            attribute: "agent_delegation",
            requested: true,
            ceiling: false,
            profile: ceiling.description,
            code: "CEILING_VIOLATION",
          });
          break;
        }
      }
    }
  }

  return violations;
}
