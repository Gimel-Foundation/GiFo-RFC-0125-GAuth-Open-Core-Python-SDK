import { Router, type Request, type Response, type NextFunction } from "express";
import { ManagementError } from "@workspace/db";
import * as mgmt from "../lib/mgmt-service";

const router = Router();

function getCaller(req: Request): string {
  return (req.headers["x-caller-identity"] as string) || "anonymous";
}

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

router.post(
  "/mandates",
  asyncHandler(async (req, res) => {
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
    const result = await mgmt.activateMandate(param(req, "id"), getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/revoke",
  asyncHandler(async (req, res) => {
    const reason = (req.body?.reason as string) ?? "";
    const result = await mgmt.revokeMandate(param(req, "id"), reason, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/suspend",
  asyncHandler(async (req, res) => {
    const reason = (req.body?.reason as string) ?? "";
    const result = await mgmt.suspendMandate(param(req, "id"), reason, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/resume",
  asyncHandler(async (req, res) => {
    const result = await mgmt.resumeMandate(param(req, "id"), getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/budget/increase",
  asyncHandler(async (req, res) => {
    const { additional_cents } = req.body;
    if (typeof additional_cents !== "number" || additional_cents <= 0) {
      throw new ManagementError("SCHEMA_VALIDATION_FAILED", "additional_cents must be a positive integer");
    }
    const result = await mgmt.increaseBudget(param(req, "id"), additional_cents, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/mandates/:id/budget/consume",
  asyncHandler(async (req, res) => {
    const { enforcement_request_id, amount_cents, description } = req.body;
    if (!enforcement_request_id || typeof amount_cents !== "number" || amount_cents <= 0) {
      throw new ManagementError(
        "SCHEMA_VALIDATION_FAILED",
        "enforcement_request_id and positive amount_cents are required",
      );
    }
    const result = await mgmt.consumeBudget(
      param(req, "id"),
      enforcement_request_id,
      amount_cents,
      description ?? "",
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
    const { additional_seconds } = req.body;
    if (typeof additional_seconds !== "number" || additional_seconds <= 0) {
      throw new ManagementError("SCHEMA_VALIDATION_FAILED", "additional_seconds must be a positive integer");
    }
    const result = await mgmt.extendTtl(param(req, "id"), additional_seconds, getCaller(req));
    res.json(result);
  }),
);

router.post(
  "/delegations",
  asyncHandler(async (req, res) => {
    const {
      parent_mandate_id,
      delegate_agent_id,
      scope_restriction,
      budget_cents,
      ttl_seconds,
    } = req.body;

    if (!parent_mandate_id || !delegate_agent_id) {
      throw new ManagementError(
        "SCHEMA_VALIDATION_FAILED",
        "parent_mandate_id and delegate_agent_id are required",
      );
    }

    const result = await mgmt.createDelegation(
      parent_mandate_id,
      delegate_agent_id,
      scope_restriction ?? {},
      budget_cents ?? 0,
      ttl_seconds ?? 3600,
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

router.get("/health", (_req, res) => {
  res.json(mgmt.getHealthInfo());
});

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
