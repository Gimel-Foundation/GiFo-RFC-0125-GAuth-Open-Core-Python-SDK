import crypto from "crypto";

const ECDSA_CRYPTOSUITE = "ecdsa-rdfc-2019";

let signingKeyPair: { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } | null = null;

function getOrCreateKeyPair(): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  if (!signingKeyPair) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    signingKeyPair = { privateKey, publicKey };
  }
  return signingKeyPair;
}

export function getVerificationPublicKey(): crypto.KeyObject {
  return getOrCreateKeyPair().publicKey;
}

function stableStringify(obj: unknown): string {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map((item) => stableStringify(item)).join(",") + "]";
  }
  const record = obj as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + stableStringify(record[k]));
  return "{" + parts.join(",") + "}";
}

function computeSigningInput(
  document: Record<string, unknown>,
  proofOptions: Record<string, unknown>,
): Buffer {
  const docHash = crypto.createHash("sha256").update(stableStringify(document)).digest();
  const optionsHash = crypto.createHash("sha256").update(stableStringify(proofOptions)).digest();
  const combined = Buffer.concat([optionsHash, docHash]);
  return crypto.createHash("sha256").update(combined).digest();
}

export function createDataIntegrityProof(
  vc: Record<string, unknown>,
  verificationMethod: string,
  challenge?: string,
): Record<string, unknown> {
  const proofOptions: Record<string, unknown> = {
    type: "DataIntegrityProof",
    cryptosuite: ECDSA_CRYPTOSUITE,
    created: new Date().toISOString(),
    verificationMethod,
    proofPurpose: "assertionMethod",
  };

  if (challenge) {
    proofOptions.challenge = challenge;
  }

  const digest = computeSigningInput(vc, proofOptions);

  const { privateKey } = getOrCreateKeyPair();
  const signature = crypto.sign(null, digest, {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  const proofValue = signature.toString("base64url");

  return { ...proofOptions, proofValue };
}

export function verifyDataIntegrityProof(
  vc: Record<string, unknown>,
  verificationKey?: crypto.KeyObject,
  expectedChallenge?: string,
): { verified: boolean; reason?: string; mode?: string; cryptosuite?: string } {
  const proof = vc.proof as Record<string, unknown> | undefined;
  if (!proof) {
    return { verified: false, reason: "No proof present" };
  }

  if (proof.type !== "DataIntegrityProof") {
    return { verified: false, reason: `Unsupported proof type: ${proof.type}` };
  }

  const suite = (proof.cryptosuite as string) || "";
  if (suite !== ECDSA_CRYPTOSUITE) {
    return { verified: false, reason: `Unsupported cryptosuite: ${suite}` };
  }

  if (expectedChallenge && proof.challenge !== expectedChallenge) {
    return { verified: false, reason: "Challenge mismatch: nonce not bound to proof" };
  }

  const vcWithoutProof: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(vc)) {
    if (k !== "proof") vcWithoutProof[k] = v;
  }

  const proofOptions: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(proof)) {
    if (k !== "proofValue") proofOptions[k] = v;
  }

  const digest = computeSigningInput(vcWithoutProof, proofOptions);
  const proofValue = proof.proofValue as string;

  const effectiveKey = verificationKey || getOrCreateKeyPair().publicKey;

  try {
    const signature = Buffer.from(proofValue, "base64url");
    const isValid = crypto.verify(null, digest, {
      key: effectiveKey,
      dsaEncoding: "ieee-p1363",
    }, signature);

    if (isValid) {
      return { verified: true, cryptosuite: suite, mode: "ecdsa" };
    }
    return { verified: false, reason: "ECDSA signature verification failed" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { verified: false, reason: `ECDSA signature verification failed: ${msg}` };
  }
}

export interface StatusListEntry {
  revoked: boolean;
  reason?: string;
}

export class BitstringStatusList {
  private bits: Uint8Array;
  private reasons: Map<number, string>;

  constructor(size = 1024) {
    this.bits = new Uint8Array(Math.ceil(size / 8));
    this.reasons = new Map();
  }

  setStatus(index: number, revoked: boolean, reason?: string): void {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    if (revoked) {
      this.bits[byteIndex] |= (1 << bitIndex);
      if (reason) this.reasons.set(index, reason);
    } else {
      this.bits[byteIndex] &= ~(1 << bitIndex);
      this.reasons.delete(index);
    }
  }

  checkRevocation(statusEntry: Record<string, unknown>): StatusListEntry {
    const index = statusEntry.statusListIndex as number;
    if (index === undefined || index === null) {
      return { revoked: false };
    }
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    const isRevoked = (this.bits[byteIndex] & (1 << bitIndex)) !== 0;
    return {
      revoked: isRevoked,
      reason: isRevoked ? this.reasons.get(index) : undefined,
    };
  }
}

export function poaToVc(
  mandate: Record<string, unknown>,
  issuerDid?: string,
  statusListCredential?: string,
  statusListIndex?: number,
): Record<string, unknown> {
  const scope = (mandate.scope || {}) as Record<string, unknown>;
  const requirements = (mandate.requirements || {}) as Record<string, unknown>;
  const parties = (mandate.parties || {}) as Record<string, unknown>;
  const budgetState = (mandate.budget_state || {}) as Record<string, unknown>;

  const effectiveIssuer = issuerDid ||
    `did:web:gauth.gimel.foundation:${parties.project_id || "default"}`;

  const subjectId = parties.subject as string || "";
  const subjectDid = subjectId ? `did:key:${subjectId}` : "";

  const coreVerbs = (scope.core_verbs || {}) as Record<string, unknown>;
  const allowedActions = Object.entries(coreVerbs)
    .filter(([, v]) => {
      if (typeof v === "object" && v !== null) return (v as Record<string, unknown>).allowed !== false;
      return Boolean(v);
    })
    .map(([k]) => k)
    .sort();

  const budget = requirements.budget as Record<string, unknown> | undefined;

  const vc: Record<string, unknown> = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://gauth.gimel.foundation/credentials/v1",
    ],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ["VerifiableCredential", "GAuthPoACredential"],
    issuer: { id: effectiveIssuer, name: "GAuth Open Core" },
    credentialSubject: {
      id: subjectDid,
      mandate_id: mandate.mandate_id || "",
      governance_profile: scope.governance_profile || "",
      phase: scope.phase || "",
      approval_mode: (requirements.approval_mode as string) || "autonomous",
      allowed_actions: allowedActions,
      allowed_sectors: scope.allowed_sectors || [],
      allowed_regions: scope.allowed_regions || [],
      allowed_decisions: scope.allowed_decisions || [],
      budget_total_cents: budgetState.total_cents || (budget?.total_cents as number) || 0,
      budget_remaining_cents: (budgetState.remaining_cents as number) || 0,
      scope_checksum: mandate.scope_checksum || "",
      tool_permissions_hash: mandate.tool_permissions_hash || "",
      platform_permissions_hash: mandate.platform_permissions_hash || "",
    },
    credentialSchema: {
      id: "https://gauth.gimel.foundation/schemas/poa-credential/v2",
      type: "JsonSchema",
    },
  };

  if (mandate.activated_at) {
    vc.validFrom = typeof mandate.activated_at === "string"
      ? mandate.activated_at
      : (mandate.activated_at as Date).toISOString();
  }
  if (mandate.expires_at) {
    vc.validUntil = typeof mandate.expires_at === "string"
      ? mandate.expires_at
      : (mandate.expires_at as Date).toISOString();
  }

  if (statusListCredential) {
    vc.credentialStatus = {
      id: `${statusListCredential}#${statusListIndex || 0}`,
      type: "BitstringStatusListEntry",
      statusPurpose: "revocation",
      statusListIndex: statusListIndex || 0,
      statusListCredential,
    };
  }

  return vc;
}
