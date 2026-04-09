import { Router, type Request, type Response, type NextFunction } from "express";
import {
  ManagementError,
  enforcementRequestSchema,
  batchEnforcementRequestSchema,
  PEP_INTERFACE_VERSION,
} from "@workspace/db";
import * as pep from "../lib/pep-service";
import { requireAuth } from "../middleware/require-auth";

const router = Router();

function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

router.use((_req, res, next) => {
  res.setHeader("X-PEP-Interface-Version", PEP_INTERFACE_VERSION);
  next();
});

router.use("/enforce", requireAuth);
router.use("/batch-enforce", requireAuth);

router.post(
  "/enforce",
  asyncHandler(async (req, res) => {
    const parsed = enforcementRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i: { path: PropertyKey[]; message: string }) => `${i.path.join(".")}: ${i.message}`).join("; ");
      res.status(422).json({
        error: { code: "SCHEMA_VALIDATION_FAILED", message: issues },
      });
      return;
    }
    const result = await pep.enforceAction(parsed.data);
    res.json(result);
  }),
);

router.post(
  "/batch-enforce",
  asyncHandler(async (req, res) => {
    const parsed = batchEnforcementRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i: { path: PropertyKey[]; message: string }) => `${i.path.join(".")}: ${i.message}`).join("; ");
      res.status(422).json({
        error: { code: "SCHEMA_VALIDATION_FAILED", message: issues },
      });
      return;
    }
    const result = await pep.batchEnforce(parsed.data.requests);
    res.json(result);
  }),
);

router.get("/policy", (_req, res) => {
  res.json(pep.getPolicy());
});

router.get("/health", (_req, res) => {
  res.json(pep.getPepHealth());
});

router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ManagementError) {
    res.status(err.httpStatus).json({
      error: { code: err.code, message: err.message },
    });
    return;
  }
  res.status(500).json({
    error: { code: "INTERNAL_ERROR", message: "Internal PEP error" },
  });
});

export default router;
