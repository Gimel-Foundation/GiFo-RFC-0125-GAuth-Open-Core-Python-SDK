import {
  pgTable,
  uuid,
  text,
  integer,
  timestamp,
  jsonb,
  boolean,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import {
  mandateStatusEnum,
  governanceProfileEnum,
  approvalModeEnum,
  phaseEnum,
  operationTypeEnum,
} from "./enums";

export const mandatesTable = pgTable("mandates", {
  mandateId: uuid("mandate_id").primaryKey().defaultRandom(),
  status: mandateStatusEnum("status").notNull().default("DRAFT"),
  governanceProfile: governanceProfileEnum("governance_profile").notNull(),
  phase: phaseEnum("phase").notNull(),
  approvalMode: approvalModeEnum("approval_mode").notNull().default("autonomous"),

  parties: jsonb("parties").notNull().$type<{
    subject: string;
    customer_id: string;
    project_id: string;
    issued_by: string;
    approval_chain?: string[];
  }>(),
  scope: jsonb("scope").notNull().$type<Record<string, unknown>>(),
  requirements: jsonb("requirements").notNull().$type<Record<string, unknown>>(),

  scopeChecksum: text("scope_checksum").notNull().default(""),
  toolPermissionsHash: text("tool_permissions_hash").notNull().default(""),
  platformPermissionsHash: text("platform_permissions_hash").notNull().default(""),

  budgetTotalCents: integer("budget_total_cents").notNull().default(0),
  budgetRemainingCents: integer("budget_remaining_cents").notNull().default(0),
  budgetConsumedCents: integer("budget_consumed_cents").notNull().default(0),
  reservedForDelegationsCents: integer("reserved_for_delegations_cents").notNull().default(0),

  ttlSeconds: integer("ttl_seconds").notNull(),

  parentMandateId: uuid("parent_mandate_id"),
  delegationDepth: integer("delegation_depth").notNull().default(0),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  activatedAt: timestamp("activated_at", { withTimezone: true }),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Mandate = typeof mandatesTable.$inferSelect;
export type InsertMandate = typeof mandatesTable.$inferInsert;

export const auditLogsTable = pgTable("audit_logs", {
  logId: uuid("log_id").primaryKey().defaultRandom(),
  mandateId: uuid("mandate_id")
    .notNull()
    .references(() => mandatesTable.mandateId),
  operationType: operationTypeEnum("operation_type").notNull(),
  callerIdentity: text("caller_identity").notNull(),
  detail: jsonb("detail").$type<Record<string, unknown>>(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AuditLog = typeof auditLogsTable.$inferSelect;
export type InsertAuditLog = typeof auditLogsTable.$inferInsert;

export const delegationsTable = pgTable("delegations", {
  delegationId: uuid("delegation_id").primaryKey().defaultRandom(),
  parentMandateId: uuid("parent_mandate_id")
    .notNull()
    .references(() => mandatesTable.mandateId),
  childMandateId: uuid("child_mandate_id")
    .notNull()
    .references(() => mandatesTable.mandateId),
  delegateAgentId: text("delegate_agent_id").notNull(),
  scopeRestriction: jsonb("scope_restriction")
    .notNull()
    .$type<Record<string, unknown>>()
    .default({}),
  depth: integer("depth").notNull().default(1),
  budgetReservedCents: integer("budget_reserved_cents").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Delegation = typeof delegationsTable.$inferSelect;
export type InsertDelegation = typeof delegationsTable.$inferInsert;

export const budgetConsumptionTable = pgTable(
  "budget_consumption",
  {
    consumptionId: uuid("consumption_id").primaryKey().defaultRandom(),
    mandateId: uuid("mandate_id")
      .notNull()
      .references(() => mandatesTable.mandateId),
    enforcementRequestId: text("enforcement_request_id").notNull(),
    amountCents: integer("amount_cents").notNull(),
    description: text("description"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("budget_consumption_enforcement_req_idx").on(
      table.enforcementRequestId,
    ),
  ],
);

export type BudgetConsumption = typeof budgetConsumptionTable.$inferSelect;
export type InsertBudgetConsumption = typeof budgetConsumptionTable.$inferInsert;
