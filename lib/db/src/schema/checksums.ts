import { createHash } from "crypto";

function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return "null";
  }
  if (typeof obj === "boolean") {
    return obj ? "true" : "false";
  }
  if (typeof obj === "number") {
    if (Number.isNaN(obj)) {
      throw new Error("NaN is not allowed in canonical JSON (RFC 8785)");
    }
    if (!Number.isFinite(obj)) {
      throw new Error("Infinity is not allowed in canonical JSON (RFC 8785)");
    }
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJson).join(",") + "]";
  }
  if (typeof obj === "object") {
    const entries = Object.entries(obj as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`);
    return "{" + entries.join(",") + "}";
  }
  return JSON.stringify(String(obj));
}

function sha256Hex(data: string): string {
  return "sha256:" + createHash("sha256").update(data, "utf-8").digest("hex");
}

export function computeScopeChecksum(
  scope: Record<string, unknown>,
): string {
  return sha256Hex(canonicalJson(scope));
}

export function computeToolPermissionsHash(
  coreVerbs: Record<string, unknown>,
): string {
  return sha256Hex(canonicalJson(coreVerbs));
}

export function computePlatformPermissionsHash(
  platformPermissions: Record<string, unknown>,
): string {
  return sha256Hex(canonicalJson(platformPermissions));
}

export { canonicalJson };
