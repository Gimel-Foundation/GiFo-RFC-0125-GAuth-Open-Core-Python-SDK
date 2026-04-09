import crypto from "node:crypto";
import { type Request, type Response, type NextFunction } from "express";
import { ManagementError } from "@workspace/db";

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  const rawAuth = req.headers["authorization"];
  const authHeader = Array.isArray(rawAuth) ? rawAuth[0] : rawAuth;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    next(
      new ManagementError(
        "INSUFFICIENT_AUTHORITY",
        "Authorization header with Bearer token is required",
      ),
    );
    return;
  }

  const token = authHeader.slice(7);
  const apiSecret = process.env.GAUTH_API_SECRET;
  if (!apiSecret) {
    next(
      new ManagementError(
        "INSUFFICIENT_AUTHORITY",
        "Server misconfigured: GAUTH_API_SECRET not set",
      ),
    );
    return;
  }

  const expected = crypto.createHmac("sha256", apiSecret).update("gauth-mgmt-v1").digest("hex");
  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(expected);
  const valid = tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf);
  if (!valid) {
    next(
      new ManagementError(
        "INSUFFICIENT_AUTHORITY",
        "Invalid API token",
      ),
    );
    return;
  }

  const rawIdentity = req.headers["x-caller-identity"];
  const identity = Array.isArray(rawIdentity) ? rawIdentity[0] : rawIdentity;
  (req as unknown as Record<string, unknown>).callerIdentity = identity || "system";
  next();
}
