import { eq, desc, and, sql } from "drizzle-orm";
import { db, pool } from "@workspace/db";
import {
  mandatesTable,
  auditLogsTable,
  delegationsTable,
  budgetConsumptionTable,
  type Mandate,
  type OperationType,
  type GovernanceProfile,
  ManagementError,
  validateMandate,
  validateDelegationScopeNarrowing,
  computeScopeChecksum,
  computeToolPermissionsHash,
  computePlatformPermissionsHash,
  getCeiling,
  CEILING_TABLE,
  governanceProfileValues,
} from "@workspace/db";
import { drizzle } from "drizzle-orm/node-postgres";

function mandateToResponse(m: Mandate) {
  const total = m.budgetTotalCents;
  const consumed = m.budgetConsumedCents;
  const remaining = m.budgetRemainingCents;
  const reserved = m.reservedForDelegationsCents;
  return {
    mandate_id: m.mandateId,
    status: m.status,
    governance_profile: m.governanceProfile,
    phase: m.phase,
    parties: m.parties,
    scope: m.scope,
    requirements: m.requirements,
    budget: {
      total_cents: total,
      remaining_cents: remaining,
      consumed_cents: consumed,
      utilization_percent: total > 0 ? Math.round((consumed / total) * 10000) / 100 : 0,
      reserved_for_delegations_cents: reserved,
    },
    scope_checksum: m.scopeChecksum,
    tool_permissions_hash: m.toolPermissionsHash,
    platform_permissions_hash: m.platformPermissionsHash,
    delegation_depth: m.delegationDepth,
    parent_mandate_id: m.parentMandateId,
    created_at: m.createdAt.toISOString(),
    activated_at: m.activatedAt?.toISOString() ?? null,
    expires_at: m.expiresAt?.toISOString() ?? null,
    updated_at: m.updatedAt.toISOString(),
  };
}

async function auditLog(
  mandateId: string,
  operationType: OperationType,
  callerIdentity: string,
  detail?: Record<string, unknown>,
) {
  await db.insert(auditLogsTable).values({
    mandateId,
    operationType,
    callerIdentity,
    detail: detail ?? {},
  });
}

async function getOrThrow(mandateId: string): Promise<Mandate> {
  const rows = await db
    .select()
    .from(mandatesTable)
    .where(eq(mandatesTable.mandateId, mandateId))
    .limit(1);
  if (rows.length === 0) {
    throw new ManagementError("MANDATE_NOT_FOUND", `Mandate ${mandateId} not found`);
  }
  return rows[0];
}

async function cascadeStatusToChildren(
  parentMandateId: string,
  newStatus: "REVOKED" | "SUSPENDED",
) {
  const children = await db
    .select()
    .from(delegationsTable)
    .where(eq(delegationsTable.parentMandateId, parentMandateId));

  for (const child of children) {
    const childMandate = await db
      .select()
      .from(mandatesTable)
      .where(eq(mandatesTable.mandateId, child.childMandateId))
      .limit(1);
    if (childMandate.length > 0 && (childMandate[0].status === "ACTIVE" || childMandate[0].status === "SUSPENDED")) {
      await db
        .update(mandatesTable)
        .set({ status: newStatus, updatedAt: new Date() })
        .where(eq(mandatesTable.mandateId, child.childMandateId));
      await auditLog(child.childMandateId, newStatus === "REVOKED" ? "REVOKE" : "SUSPEND", "system", {
        reason: `Cascaded from parent ${parentMandateId}`,
      });
      await cascadeStatusToChildren(child.childMandateId, newStatus);
    }
  }
}

async function cascadeResumeToChildren(parentMandateId: string) {
  const children = await db
    .select()
    .from(delegationsTable)
    .where(eq(delegationsTable.parentMandateId, parentMandateId));

  for (const child of children) {
    const childMandate = await db
      .select()
      .from(mandatesTable)
      .where(eq(mandatesTable.mandateId, child.childMandateId))
      .limit(1);
    if (childMandate.length > 0 && childMandate[0].status === "SUSPENDED") {
      const now = new Date();
      if (childMandate[0].expiresAt && childMandate[0].expiresAt <= now) {
        await db
          .update(mandatesTable)
          .set({ status: "EXPIRED", updatedAt: now })
          .where(eq(mandatesTable.mandateId, child.childMandateId));
        await auditLog(child.childMandateId, "RESUME", "system", {
          reason: "Expired during suspension",
        });
      } else {
        await db
          .update(mandatesTable)
          .set({ status: "ACTIVE", updatedAt: now })
          .where(eq(mandatesTable.mandateId, child.childMandateId));
        await auditLog(child.childMandateId, "RESUME", "system", {
          reason: `Cascaded resume from parent ${parentMandateId}`,
        });
        await cascadeResumeToChildren(child.childMandateId);
      }
    }
  }
}

export async function createMandate(body: Record<string, unknown>, caller: string) {
  const validation = validateMandate(body);
  if (!validation.accepted) {
    throw new ManagementError("SCHEMA_VALIDATION_FAILED", JSON.stringify({
      schema_errors: validation.schemaErrors,
      ceiling_violations: validation.ceilingViolations,
      consistency_errors: validation.consistencyErrors,
    }));
  }

  const parties = body.parties as Record<string, unknown>;
  const scope = body.scope as Record<string, unknown>;
  const requirements = body.requirements as Record<string, unknown>;
  const budget = requirements.budget as Record<string, unknown>;
  const totalCents = budget.total_cents as number;
  const ttlSeconds = requirements.ttl_seconds as number;

  const scopeChecksum = computeScopeChecksum(scope);
  const toolPermissionsHash = computeToolPermissionsHash(
    (scope.core_verbs ?? {}) as Record<string, unknown>,
  );
  const platformPermissionsHash = computePlatformPermissionsHash(
    (scope.platform_permissions ?? {}) as Record<string, unknown>,
  );

  const rows = await db
    .insert(mandatesTable)
    .values({
      status: "DRAFT",
      governanceProfile: scope.governance_profile as GovernanceProfile,
      phase: scope.phase as "plan" | "build" | "run",
      approvalMode: (requirements.approval_mode as "autonomous" | "supervised" | "four-eyes") ?? "autonomous",
      parties: parties as Mandate["parties"],
      scope,
      requirements,
      scopeChecksum,
      toolPermissionsHash,
      platformPermissionsHash,
      budgetTotalCents: totalCents,
      budgetRemainingCents: totalCents,
      budgetConsumedCents: 0,
      reservedForDelegationsCents: 0,
      ttlSeconds,
    })
    .returning();

  const mandate = rows[0];
  await auditLog(mandate.mandateId, "CREATE", caller);

  return {
    mandate_id: mandate.mandateId,
    status: "DRAFT" as const,
    governance_profile: mandate.governanceProfile,
    scope_checksum: scopeChecksum,
    tool_permissions_hash: toolPermissionsHash,
    platform_permissions_hash: platformPermissionsHash,
    created_at: mandate.createdAt.toISOString(),
    validation: {
      accepted: true,
      schema_errors: [],
      ceiling_violations: [],
      consistency_errors: [],
    },
  };
}

export async function getMandate(mandateId: string) {
  const m = await getOrThrow(mandateId);
  return mandateToResponse(m);
}

export async function listMandates(params: {
  status?: string;
  agent_id?: string;
  project_id?: string;
  governance_profile?: string;
  cursor?: string;
  limit?: number;
}) {
  const limit = Math.min(params.limit ?? 20, 100);
  const conditions: ReturnType<typeof eq>[] = [];

  if (params.status) {
    conditions.push(eq(mandatesTable.status, params.status as Mandate["status"]));
  }
  if (params.governance_profile) {
    conditions.push(
      eq(mandatesTable.governanceProfile, params.governance_profile as GovernanceProfile),
    );
  }

  if (params.cursor) {
    const cursorMandate = await db
      .select({ createdAt: mandatesTable.createdAt })
      .from(mandatesTable)
      .where(eq(mandatesTable.mandateId, params.cursor))
      .limit(1);
    if (cursorMandate.length > 0) {
      conditions.push(
        sql`${mandatesTable.createdAt} < ${cursorMandate[0].createdAt}`,
      );
    }
  }

  const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

  const allRows = await db
    .select()
    .from(mandatesTable)
    .where(whereClause)
    .orderBy(desc(mandatesTable.createdAt))
    .limit(limit);

  let filteredRows = allRows;
  if (params.agent_id) {
    filteredRows = filteredRows.filter(
      (r) => r.parties.subject === params.agent_id,
    );
  }
  if (params.project_id) {
    filteredRows = filteredRows.filter(
      (r) => r.parties.project_id === params.project_id,
    );
  }

  const items = filteredRows.map(mandateToResponse);
  const nextCursor =
    items.length === limit ? items[items.length - 1].mandate_id : null;

  const countResult = await db
    .select({ count: sql<number>`count(*)::int` })
    .from(mandatesTable)
    .where(
      conditions.filter((c) => c !== conditions[conditions.length - 1] || !params.cursor).length > 0
        ? and(...conditions.filter((_, i) => !(params.cursor && i === conditions.length - 1)))
        : undefined,
    );
  const total = countResult[0]?.count ?? 0;

  return { items, next_cursor: nextCursor, total };
}

export async function deleteMandate(mandateId: string, caller: string) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "DRAFT") {
    throw new ManagementError("MANDATE_NOT_DRAFT", "Only DRAFT mandates can be deleted");
  }

  await db
    .update(mandatesTable)
    .set({ status: "DELETED", updatedAt: new Date() })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "DELETE", caller);

  return { mandate_id: mandateId, deleted: true };
}

export async function getMandateHistory(mandateId: string) {
  await getOrThrow(mandateId);
  const logs = await db
    .select()
    .from(auditLogsTable)
    .where(eq(auditLogsTable.mandateId, mandateId))
    .orderBy(desc(auditLogsTable.createdAt));

  return logs.map((l) => ({
    log_id: l.logId,
    mandate_id: l.mandateId,
    operation_type: l.operationType,
    caller_identity: l.callerIdentity,
    detail: l.detail,
    created_at: l.createdAt.toISOString(),
  }));
}

export async function activateMandate(mandateId: string, caller: string) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "DRAFT") {
    throw new ManagementError("MANDATE_NOT_DRAFT", "Only DRAFT mandates can be activated");
  }

  const revalidation = validateMandate({
    parties: m.parties,
    scope: m.scope,
    requirements: m.requirements,
  });
  if (!revalidation.accepted) {
    throw new ManagementError("SCHEMA_VALIDATION_FAILED", "Re-validation failed on activation");
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + m.ttlSeconds * 1000);

  const client = await pool.connect();
  try {
    const txDb = drizzle(client);
    await client.query("BEGIN");

    const existingActive = await txDb
      .select({ mandateId: mandatesTable.mandateId })
      .from(mandatesTable)
      .where(
        and(
          sql`(${mandatesTable.parties}->>'subject')::text = ${m.parties.subject}`,
          sql`(${mandatesTable.parties}->>'project_id')::text = ${m.parties.project_id}`,
          eq(mandatesTable.status, "ACTIVE"),
        ),
      );

    for (const active of existingActive) {
      await txDb
        .update(mandatesTable)
        .set({ status: "SUPERSEDED", updatedAt: now })
        .where(eq(mandatesTable.mandateId, active.mandateId));
      await txDb.insert(auditLogsTable).values({
        mandateId: active.mandateId,
        operationType: "SUPERSEDE",
        callerIdentity: caller,
        detail: { superseded_by: mandateId },
      });
    }

    await txDb
      .update(mandatesTable)
      .set({
        status: "ACTIVE",
        activatedAt: now,
        expiresAt,
        updatedAt: now,
      })
      .where(eq(mandatesTable.mandateId, mandateId));
    await txDb.insert(auditLogsTable).values({
      mandateId,
      operationType: "ACTIVATE",
      callerIdentity: caller,
      detail: existingActive.length > 0
        ? { superseded_mandates: existingActive.map((a) => a.mandateId) }
        : {},
    });

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }

  return {
    mandate_id: mandateId,
    status: "ACTIVE" as const,
    activated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
  };
}

export async function revokeMandate(mandateId: string, reason: string, caller: string) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "ACTIVE" && m.status !== "SUSPENDED") {
    throw new ManagementError(
      "INVALID_STATE_TRANSITION",
      `Cannot revoke mandate in status ${m.status}`,
    );
  }

  const now = new Date();
  await db
    .update(mandatesTable)
    .set({ status: "REVOKED", updatedAt: now })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "REVOKE", caller, { reason });
  await cascadeStatusToChildren(mandateId, "REVOKED");

  return {
    mandate_id: mandateId,
    status: "REVOKED" as const,
    reason,
    revoked_at: now.toISOString(),
  };
}

export async function suspendMandate(mandateId: string, reason: string, caller: string) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "ACTIVE") {
    throw new ManagementError("MANDATE_NOT_ACTIVE", "Only ACTIVE mandates can be suspended");
  }

  const now = new Date();
  await db
    .update(mandatesTable)
    .set({ status: "SUSPENDED", updatedAt: now })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "SUSPEND", caller, { reason });
  await cascadeStatusToChildren(mandateId, "SUSPENDED");

  return {
    mandate_id: mandateId,
    status: "SUSPENDED" as const,
    reason,
    suspended_at: now.toISOString(),
  };
}

export async function resumeMandate(mandateId: string, caller: string) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "SUSPENDED") {
    throw new ManagementError("MANDATE_NOT_SUSPENDED", "Only SUSPENDED mandates can be resumed");
  }

  const now = new Date();
  if (m.expiresAt && m.expiresAt <= now) {
    await db
      .update(mandatesTable)
      .set({ status: "EXPIRED", updatedAt: now })
      .where(eq(mandatesTable.mandateId, mandateId));
    await auditLog(mandateId, "RESUME", caller, { reason: "Expired during suspension" });
    throw new ManagementError("MANDATE_EXPIRED", "Mandate expired during suspension");
  }

  await db
    .update(mandatesTable)
    .set({ status: "ACTIVE", updatedAt: now })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "RESUME", caller);
  await cascadeResumeToChildren(mandateId);

  return {
    mandate_id: mandateId,
    status: "ACTIVE" as const,
    resumed_at: now.toISOString(),
  };
}

export async function increaseBudget(
  mandateId: string,
  additionalCents: number,
  caller: string,
) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "ACTIVE" && m.status !== "SUSPENDED") {
    throw new ManagementError("MANDATE_NOT_ACTIVE", "Budget can only be increased on ACTIVE or SUSPENDED mandates");
  }

  const newTotal = m.budgetTotalCents + additionalCents;
  const newRemaining = m.budgetRemainingCents + additionalCents;

  await db
    .update(mandatesTable)
    .set({
      budgetTotalCents: newTotal,
      budgetRemainingCents: newRemaining,
      updatedAt: new Date(),
    })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "BUDGET_INCREASE", caller, { additional_cents: additionalCents });

  return {
    mandate_id: mandateId,
    budget: {
      total_cents: newTotal,
      remaining_cents: newRemaining,
      consumed_cents: m.budgetConsumedCents,
      utilization_percent:
        newTotal > 0
          ? Math.round((m.budgetConsumedCents / newTotal) * 10000) / 100
          : 0,
      reserved_for_delegations_cents: m.reservedForDelegationsCents,
    },
    additional_cents: additionalCents,
    increased_by: caller,
  };
}

export async function consumeBudget(
  mandateId: string,
  enforcementRequestId: string,
  amountCents: number,
  description: string,
) {
  const existing = await db
    .select()
    .from(budgetConsumptionTable)
    .where(eq(budgetConsumptionTable.enforcementRequestId, enforcementRequestId))
    .limit(1);

  if (existing.length > 0) {
    const m = await getOrThrow(mandateId);
    return {
      mandate_id: mandateId,
      enforcement_request_id: enforcementRequestId,
      amount_cents: existing[0].amountCents,
      budget: {
        total_cents: m.budgetTotalCents,
        remaining_cents: m.budgetRemainingCents,
        consumed_cents: m.budgetConsumedCents,
        utilization_percent:
          m.budgetTotalCents > 0
            ? Math.round((m.budgetConsumedCents / m.budgetTotalCents) * 10000) / 100
            : 0,
        reserved_for_delegations_cents: m.reservedForDelegationsCents,
      },
    };
  }

  const client = await pool.connect();
  try {
    const txDb = drizzle(client);
    await client.query("BEGIN");

    const rows = await txDb
      .select()
      .from(mandatesTable)
      .where(eq(mandatesTable.mandateId, mandateId))
      .limit(1);
    if (rows.length === 0) {
      throw new ManagementError("MANDATE_NOT_FOUND", `Mandate ${mandateId} not found`);
    }
    const m = rows[0];

    if (m.status !== "ACTIVE") {
      throw new ManagementError("MANDATE_NOT_ACTIVE", "Budget can only be consumed on ACTIVE mandates");
    }
    if (amountCents > m.budgetRemainingCents) {
      throw new ManagementError(
        "DELEGATION_BUDGET_EXCEEDED",
        `Insufficient budget: ${amountCents} > ${m.budgetRemainingCents} remaining`,
      );
    }

    const newRemaining = m.budgetRemainingCents - amountCents;
    const newConsumed = m.budgetConsumedCents + amountCents;
    const newStatus = newRemaining <= 0 ? "BUDGET_EXCEEDED" : "ACTIVE";

    try {
      await txDb.insert(budgetConsumptionTable).values({
        mandateId,
        enforcementRequestId,
        amountCents,
        description: description || null,
      });
    } catch (insertErr: unknown) {
      if (
        insertErr instanceof Error &&
        insertErr.message.includes("duplicate key")
      ) {
        await client.query("ROLLBACK");
        const currentM = await getOrThrow(mandateId);
        return {
          mandate_id: mandateId,
          enforcement_request_id: enforcementRequestId,
          amount_cents: amountCents,
          budget: {
            total_cents: currentM.budgetTotalCents,
            remaining_cents: currentM.budgetRemainingCents,
            consumed_cents: currentM.budgetConsumedCents,
            utilization_percent:
              currentM.budgetTotalCents > 0
                ? Math.round((currentM.budgetConsumedCents / currentM.budgetTotalCents) * 10000) / 100
                : 0,
            reserved_for_delegations_cents: currentM.reservedForDelegationsCents,
          },
        };
      }
      throw insertErr;
    }

    await txDb
      .update(mandatesTable)
      .set({
        budgetRemainingCents: newRemaining,
        budgetConsumedCents: newConsumed,
        status: newStatus as Mandate["status"],
        updatedAt: new Date(),
      })
      .where(eq(mandatesTable.mandateId, mandateId));

    const auditDetail: Record<string, unknown> = {
      enforcement_request_id: enforcementRequestId,
      amount_cents: amountCents,
    };
    if (newStatus === "BUDGET_EXCEEDED") {
      auditDetail.auto_transition = "BUDGET_EXCEEDED";
    }
    await txDb.insert(auditLogsTable).values({
      mandateId,
      operationType: "BUDGET_CONSUME",
      callerIdentity: "pep",
      detail: auditDetail,
    });

    await client.query("COMMIT");

    return {
      mandate_id: mandateId,
      enforcement_request_id: enforcementRequestId,
      amount_cents: amountCents,
      budget: {
        total_cents: m.budgetTotalCents,
        remaining_cents: newRemaining,
        consumed_cents: newConsumed,
        utilization_percent:
          m.budgetTotalCents > 0
            ? Math.round((newConsumed / m.budgetTotalCents) * 10000) / 100
            : 0,
        reserved_for_delegations_cents: m.reservedForDelegationsCents,
      },
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function getBudget(mandateId: string) {
  const m = await getOrThrow(mandateId);
  return {
    total_cents: m.budgetTotalCents,
    remaining_cents: m.budgetRemainingCents,
    consumed_cents: m.budgetConsumedCents,
    utilization_percent:
      m.budgetTotalCents > 0
        ? Math.round((m.budgetConsumedCents / m.budgetTotalCents) * 10000) / 100
        : 0,
    reserved_for_delegations_cents: m.reservedForDelegationsCents,
  };
}

export async function extendTtl(
  mandateId: string,
  additionalSeconds: number,
  caller: string,
) {
  const m = await getOrThrow(mandateId);
  if (m.status !== "ACTIVE" && m.status !== "SUSPENDED") {
    throw new ManagementError("MANDATE_NOT_ACTIVE", "TTL can only be extended on ACTIVE or SUSPENDED mandates");
  }

  const newTtl = m.ttlSeconds + additionalSeconds;

  const ceiling = getCeiling(m.governanceProfile);
  if (ceiling.maxSessionDurationMinutes !== null) {
    const maxTtlSeconds = ceiling.maxSessionDurationMinutes * 60;
    if (newTtl > maxTtlSeconds) {
      throw new ManagementError(
        "CEILING_VIOLATION",
        `Extended TTL ${newTtl}s exceeds profile ceiling ${maxTtlSeconds}s (${ceiling.maxSessionDurationMinutes} min)`,
      );
    }
  }

  const newExpiresAt = m.expiresAt
    ? new Date(m.expiresAt.getTime() + additionalSeconds * 1000)
    : null;

  await db
    .update(mandatesTable)
    .set({
      ttlSeconds: newTtl,
      expiresAt: newExpiresAt,
      updatedAt: new Date(),
    })
    .where(eq(mandatesTable.mandateId, mandateId));
  await auditLog(mandateId, "TTL_EXTEND", caller, { additional_seconds: additionalSeconds });

  return {
    mandate_id: mandateId,
    ttl_seconds: newTtl,
    expires_at: newExpiresAt?.toISOString() ?? "",
    additional_seconds: additionalSeconds,
    extended_by: caller,
  };
}

export async function createDelegation(
  parentMandateId: string,
  delegateAgentId: string,
  scopeRestriction: Record<string, unknown>,
  budgetCents: number,
  ttlSeconds: number,
  caller: string,
) {
  const parent = await getOrThrow(parentMandateId);
  if (parent.status !== "ACTIVE") {
    throw new ManagementError("PARENT_MANDATE_NOT_ACTIVE", "Parent mandate must be ACTIVE");
  }

  const ceiling = getCeiling(parent.governanceProfile);
  const newDepth = parent.delegationDepth + 1;
  if (newDepth > ceiling.maxDelegationDepth) {
    throw new ManagementError(
      "DELEGATION_DEPTH_EXCEEDED",
      `Depth ${newDepth} exceeds ceiling ${ceiling.maxDelegationDepth}`,
    );
  }

  if (budgetCents > parent.budgetRemainingCents) {
    throw new ManagementError(
      "DELEGATION_BUDGET_EXCEEDED",
      `Requested ${budgetCents} exceeds parent remaining ${parent.budgetRemainingCents}`,
    );
  }

  if (parent.expiresAt) {
    const parentRemainingSeconds = Math.floor(
      (parent.expiresAt.getTime() - Date.now()) / 1000,
    );
    if (ttlSeconds > parentRemainingSeconds) {
      throw new ManagementError(
        "DELEGATION_TTL_EXCEEDED",
        `TTL ${ttlSeconds}s exceeds parent remaining ${parentRemainingSeconds}s`,
      );
    }
  }

  const parentScope = parent.scope as Record<string, unknown>;
  const childScope = { ...parentScope };

  if (Object.keys(scopeRestriction).length > 0) {
    const narrowingErrors = validateDelegationScopeNarrowing(parentScope, {
      ...parentScope,
      ...scopeRestriction,
    });
    if (narrowingErrors.length > 0) {
      throw new ManagementError(
        "DELEGATION_SCOPE_WIDENING",
        JSON.stringify(narrowingErrors),
      );
    }

    for (const [key, value] of Object.entries(scopeRestriction)) {
      if (key in childScope) {
        const listKeys = new Set([
          "allowed_paths", "allowed_sectors", "allowed_regions",
          "allowed_transactions", "allowed_decisions",
        ]);
        if (listKeys.has(key) && Array.isArray(value) && Array.isArray(childScope[key])) {
          const parentSet = new Set(childScope[key] as string[]);
          childScope[key] = (value as string[]).filter((v) => parentSet.has(v));
        } else if (key === "core_verbs" && typeof value === "object" && value !== null) {
          const parentVerbs = (childScope[key] ?? {}) as Record<string, Record<string, unknown>>;
          const restrictedVerbs = value as Record<string, Record<string, unknown>>;
          const narrowed: Record<string, Record<string, unknown>> = {};
          for (const [vk, vv] of Object.entries(parentVerbs)) {
            if (vk in restrictedVerbs) {
              const pPolicy = typeof vv === "object" && vv !== null ? vv : { allowed: Boolean(vv) };
              const cPolicy = typeof restrictedVerbs[vk] === "object" && restrictedVerbs[vk] !== null
                ? restrictedVerbs[vk]
                : { allowed: Boolean(restrictedVerbs[vk]) };
              narrowed[vk] = {
                ...pPolicy,
                allowed: (pPolicy.allowed !== false) && (cPolicy.allowed !== false),
                requires_approval: Boolean(pPolicy.requires_approval) || Boolean(cPolicy.requires_approval),
              };
            }
          }
          childScope[key] = narrowed;
        } else if (key === "platform_permissions" && typeof value === "object" && value !== null) {
          const parentDict = (childScope[key] ?? {}) as Record<string, unknown>;
          const childDict: Record<string, unknown> = {};
          for (const [dk, dv] of Object.entries(parentDict)) {
            if (dk in (value as Record<string, unknown>)) {
              const cv = (value as Record<string, unknown>)[dk];
              if (typeof dv === "boolean" && typeof cv === "boolean") {
                childDict[dk] = dv && cv;
              } else if (Array.isArray(dv) && Array.isArray(cv)) {
                const parentArr = new Set(dv as string[]);
                childDict[dk] = (cv as string[]).filter((v) => parentArr.has(v));
              } else {
                childDict[dk] = dv;
              }
            } else {
              childDict[dk] = dv;
            }
          }
          childScope[key] = childDict;
        }
      }
    }
  }

  const scopeChecksum = computeScopeChecksum(childScope);
  const toolPermissionsHash = computeToolPermissionsHash(
    (childScope.core_verbs ?? {}) as Record<string, unknown>,
  );
  const platformPermissionsHash = computePlatformPermissionsHash(
    (childScope.platform_permissions ?? {}) as Record<string, unknown>,
  );

  const now = new Date();
  const childExpiresAt = new Date(now.getTime() + ttlSeconds * 1000);

  const client = await pool.connect();
  try {
    const txDb = drizzle(client);
    await client.query("BEGIN");

    await txDb
      .update(mandatesTable)
      .set({
        budgetRemainingCents: parent.budgetRemainingCents - budgetCents,
        reservedForDelegationsCents: parent.reservedForDelegationsCents + budgetCents,
        updatedAt: now,
      })
      .where(eq(mandatesTable.mandateId, parentMandateId));

    const childRows = await txDb
      .insert(mandatesTable)
      .values({
        status: "ACTIVE",
        governanceProfile: parent.governanceProfile,
        phase: parent.phase,
        approvalMode: parent.approvalMode,
        parties: {
          subject: delegateAgentId,
          customer_id: parent.parties.customer_id,
          project_id: parent.parties.project_id,
          issued_by: caller,
        },
        scope: childScope,
        requirements: parent.requirements,
        scopeChecksum,
        toolPermissionsHash,
        platformPermissionsHash,
        budgetTotalCents: budgetCents,
        budgetRemainingCents: budgetCents,
        budgetConsumedCents: 0,
        reservedForDelegationsCents: 0,
        ttlSeconds,
        parentMandateId,
        delegationDepth: newDepth,
        activatedAt: now,
        expiresAt: childExpiresAt,
      })
      .returning();

    const child = childRows[0];

    await txDb.insert(delegationsTable).values({
      parentMandateId,
      childMandateId: child.mandateId,
      delegateAgentId,
      scopeRestriction,
      depth: newDepth,
      budgetReservedCents: budgetCents,
    });

    await txDb.insert(auditLogsTable).values({
      mandateId: parentMandateId,
      operationType: "DELEGATE",
      callerIdentity: caller,
      detail: {
        child_mandate_id: child.mandateId,
        delegate_agent_id: delegateAgentId,
        budget_cents: budgetCents,
      },
    });
    await txDb.insert(auditLogsTable).values({
      mandateId: child.mandateId,
      operationType: "CREATE",
      callerIdentity: caller,
      detail: {
        parent_mandate_id: parentMandateId,
        delegation_depth: newDepth,
      },
    });

    await client.query("COMMIT");

    return {
      mandate_id: child.mandateId,
      parent_mandate_id: parentMandateId,
      delegate_agent_id: delegateAgentId,
      delegation_depth: newDepth,
      budget: {
        total_cents: budgetCents,
        remaining_cents: budgetCents,
        consumed_cents: 0,
        utilization_percent: 0,
        reserved_for_delegations_cents: 0,
      },
      scope: childScope,
      created_at: child.createdAt.toISOString(),
      expires_at: childExpiresAt.toISOString(),
    };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function getDelegationChain(mandateId: string) {
  await getOrThrow(mandateId);

  const chain: Array<{
    mandate_id: string;
    parent_mandate_id: string | null;
    delegation_depth: number;
    delegate_agent_id: string;
    scope: Record<string, unknown>;
    budget_reserved_cents: number;
  }> = [];

  let currentId: string | null = mandateId;
  const visited = new Set<string>();

  while (currentId && !visited.has(currentId)) {
    visited.add(currentId);
    const m = await db
      .select()
      .from(mandatesTable)
      .where(eq(mandatesTable.mandateId, currentId))
      .limit(1);
    if (m.length === 0) break;

    const delegation = m[0].parentMandateId
      ? await db
          .select()
          .from(delegationsTable)
          .where(eq(delegationsTable.childMandateId, currentId))
          .limit(1)
      : [];

    chain.unshift({
      mandate_id: m[0].mandateId,
      parent_mandate_id: m[0].parentMandateId,
      delegation_depth: m[0].delegationDepth,
      delegate_agent_id: m[0].parties.subject,
      scope: m[0].scope as Record<string, unknown>,
      budget_reserved_cents: delegation[0]?.budgetReservedCents ?? 0,
    });

    currentId = m[0].parentMandateId;
  }

  return { mandate_id: mandateId, chain };
}

export function listProfiles() {
  return (governanceProfileValues as readonly string[]).map((p) => {
    const ceiling = CEILING_TABLE[p as GovernanceProfile];
    return {
      name: p,
      description: ceiling.description,
      registration_context: ceiling.registrationContext,
    };
  });
}

export function getProfileCeilings(profile: string) {
  if (!(governanceProfileValues as readonly string[]).includes(profile)) {
    throw new ManagementError("PROFILE_NOT_FOUND", `Profile ${profile} not found`);
  }
  const ceiling = getCeiling(profile as GovernanceProfile);
  return {
    name: profile,
    deployment_targets: [...ceiling.deploymentTargets],
    auto_deploy: ceiling.autoDeploy,
    db_write: ceiling.dbWrite,
    db_migration: ceiling.dbMigration,
    db_production: ceiling.dbProduction,
    shell_mode: ceiling.shellMode,
    packages_audited_only: ceiling.packagesAuditedOnly,
    secrets_read: ceiling.secretsRead,
    secrets_create: ceiling.secretsCreate,
    agent_delegation: ceiling.agentDelegation,
    max_delegation_depth: ceiling.maxDelegationDepth,
    min_approval_mode: ceiling.minApprovalMode,
    max_session_duration_minutes: ceiling.maxSessionDurationMinutes,
    max_tool_calls: ceiling.maxToolCalls,
    max_lines_per_commit: ceiling.maxLinesPerCommit,
    description: ceiling.description,
    registration_context: ceiling.registrationContext,
  };
}

export function getHealthInfo() {
  return {
    status: "ok",
    mgmt_version: "1.1.0",
    interface_version: "1.1",
    supported_schema_version: "0116.2.2",
    feature_flags: {
      delegation: true,
      budget_tracking: true,
      ttl_extension: true,
      cascade_revocation: true,
      cascade_suspension: true,
      audit_logging: true,
    },
  };
}
