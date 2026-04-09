import { Router, type Request, type Response, type NextFunction } from "express";
import {
  ManagementError,
  mandateCreationRequestSchema,
  mandateRevocationRequestSchema,
  mandateSuspensionRequestSchema,
  mandateResumptionRequestSchema,
  mandateActivationRequestSchema,
  budgetIncreaseRequestSchema,
  consumptionReportSchema,
  ttlExtensionRequestSchema,
  delegationRequestSchema,
} from "@workspace/db";
import * as mgmt from "../lib/mgmt-service";

const router = Router();

function param(req: Request, name: string): string {
  const v = req.params[name];
  return Array.isArray(v) ? v[0] : v;
}

function asyncHandler(
  fn: (req: Request, res: Response) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

function requireAuth(req: Request, _res: Response, next: NextFunction) {
  const identity = req.headers["x-caller-identity"];
  if (!identity || (typeof identity === "string" && identity.trim() === "")) {
    next(
      new ManagementError(
        "INSUFFICIENT_AUTHORITY",
        "X-Caller-Identity header is required for management operations",
      ),
    );
    return;
  }
  next();
}

function getCaller(req: Request): string {
  return req.headers["x-caller-identity"] as string;
}

function zodParse(
  schema: { safeParse: (data: unknown) => { success: boolean; data?: unknown; error?: { issues: Array<{ path: PropertyKey[]; message: string }> } } },
  data: unknown,
) {
  const result = schema.safeParse(data);
  if (!result.success) {
    const messages = result.error!.issues
      .map((i) => `${i.path.map(String).join(".")}: ${i.message}`)
      .join("; ");
    throw new ManagementError("SCHEMA_VALIDATION_FAILED", messages);
  }
  return result.data as Record<string, unknown>;
}

router.use(requireAuth);

router.get("/health", (_req, res) => {
  res.json(mgmt.getHealthInfo());
});

router.get("/profiles", (_req, res) => {
  res.json(mgmt.listProfiles());
});

router.get(
  "/profiles/:profile/ceilings",
  asyncHandler(async (req, res) => {
    const result = mgmt.getProfileCeilings(param(req, "profile"));
    res.json(result);
  }),
);

router.post(
  "/mandates",
  asyncHandler(async (req, res) => {
    zodParse(mandateCreationRequestSchema, req.body);
    const result = await mgmt.createMandate(req.body, getCaller(req));
    res.status(201).json(result);
  }),
);

router.get(
  "/mandates",
  asyncHandler(async (req, res) => {
    const result = await mgmt.listMandates({
      status: req.query.status as string | undefined,
      agent_id: req.query.agent_id as string | undefined,
      project_id: req.query.project_id as string | undefined,
      governance_profile: req.query.governance_profile as string | undefined,
      cursor: req.query.cursor as string | undefined,
      limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
    });
    res.json(result);
  }),
);

router.get(
  "/mandates/:id",
  asyncHandler(async (req, res) => {
    const result = await mgmt.getMandate(param(req, "id"));
    res.json(result);
  }),
);

router.delete(
  "/mandates/:id",
  asyncHandler(async (req, res) => {
    const result = await mgmt.deleteMandate(param(req, "id"), getCaller(req));
    res.json(result);
  }),
);

router.get(
  "/mandates/:id/history",
  asyncHandler(async (req, res) => {
    const result = await mgmt.getMandateHistory(param(req, "id"));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/activate",
  asyncHandler(async (req, res) => {
    zodParse(mandateActivationRequestSchema, {
      mandate_id: param(req, "id"),
      activated_by: getCaller(req),
    });
    const result = await mgmt.activateMandate(param(req, "id"), getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/revoke",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(mandateRevocationRequestSchema, {
      mandate_id: param(req, "id"),
      reason: req.body?.reason ?? "",
      revoked_by: getCaller(req),
    });
    const result = await mgmt.revokeMandate(param(req, "id"), parsed.reason as string, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/suspend",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(mandateSuspensionRequestSchema, {
      mandate_id: param(req, "id"),
      reason: req.body?.reason ?? "",
      suspended_by: getCaller(req),
    });
    const result = await mgmt.suspendMandate(param(req, "id"), parsed.reason as string, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/resume",
  asyncHandler(async (req, res) => {
    zodParse(mandateResumptionRequestSchema, {
      mandate_id: param(req, "id"),
      resumed_by: getCaller(req),
    });
    const result = await mgmt.resumeMandate(param(req, "id"), getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/budget/increase",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(budgetIncreaseRequestSchema, {
      mandate_id: param(req, "id"),
      additional_cents: req.body?.additional_cents,
      increased_by: getCaller(req),
    });
    const result = await mgmt.increaseBudget(
      param(req, "id"),
      parsed.additional_cents as number,
      getCaller(req),
    );
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/budget/consume",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(consumptionReportSchema, {
      mandate_id: param(req, "id"),
      enforcement_request_id: req.body?.enforcement_request_id,
      amount_cents: req.body?.amount_cents,
      description: req.body?.description ?? "",
    });
    const result = await mgmt.consumeBudget(
      param(req, "id"),
      parsed.enforcement_request_id as string,
      parsed.amount_cents as number,
      parsed.description as string,
      getCaller(req),
    );
    res.json(result);
  }),
);

router.get(
  "/mandates/:id/budget",
  asyncHandler(async (req, res) => {
    const result = await mgmt.getBudget(param(req, "id"));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/ttl/extend",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(ttlExtensionRequestSchema, {
      mandate_id: param(req, "id"),
      additional_seconds: req.body?.additional_seconds,
      extended_by: getCaller(req),
    });
    const result = await mgmt.extendTtl(
      param(req, "id"),
      parsed.additional_seconds as number,
      getCaller(req),
    );
    res.json(result);
  }),
);

router.post(
  "/delegations",
  asyncHandler(async (req, res) => {
    const parsed = zodParse(delegationRequestSchema, {
      parent_mandate_id: req.body?.parent_mandate_id,
      delegate_agent_id: req.body?.delegate_agent_id,
      scope_restriction: req.body?.scope_restriction ?? {},
      budget_cents: req.body?.budget_cents,
      ttl_seconds: req.body?.ttl_seconds,
      delegated_by: getCaller(req),
    });
    const result = await mgmt.createDelegation(
      parsed.parent_mandate_id as string,
      parsed.delegate_agent_id as string,
      (parsed.scope_restriction ?? {}) as Record<string, unknown>,
      parsed.budget_cents as number,
      parsed.ttl_seconds as number,
      getCaller(req),
    );
    res.status(201).json(result);
  }),
);

router.get(
  "/mandates/:id/delegation-chain",
  asyncHandler(async (req, res) => {
    const result = await mgmt.getDelegationChain(param(req, "id"));
    res.json(result);
  }),
);

router.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ManagementError) {
    res.status(err.httpStatus).json({
      error: {
        code: err.code,
        message: err.message,
      },
    });
    return;
  }
  res.status(500).json({
    error: {
      code: "INTERNAL_ERROR",
      message: err.message || "Internal server error",
    },
  });
});

export default router;
