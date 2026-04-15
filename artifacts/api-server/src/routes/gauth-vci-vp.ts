import crypto from "crypto";
import { Router, type Request, type Response, type NextFunction } from "express";
import { ManagementError } from "@workspace/db";

const router = Router();

interface NonceEntry {
  expiresAt: number;
  used: boolean;
}

interface CodeEntry {
  mandate: Record<string, unknown>;
  credentialType: string;
  consumed: boolean;
  createdAt: number;
}

interface TokenEntry {
  mandate: Record<string, unknown>;
  credentialType: string;
  expiresAt: number;
}

interface VPSession {
  status: "pending" | "verified" | "rejected" | "expired";
  nonce: string;
  credentialTypes: string[];
  createdAt: number;
  expiresAt: number;
  vpToken?: unknown;
}

const nonces = new Map<string, NonceEntry>();
const usedNonces = new Set<string>();
const codes = new Map<string, CodeEntry>();
const tokens = new Map<string, TokenEntry>();
const offers = new Map<string, Record<string, unknown>>();
const vpSessions = new Map<string, VPSession>();

const NONCE_TTL = 300;
const TOKEN_TTL = 3600;
const SESSION_TTL = 600;

function issueNonce(ttl = NONCE_TTL): { nonce: string; ttl: number } {
  const nonce = `c_nonce_${crypto.randomBytes(24).toString("base64url")}`;
  nonces.set(nonce, { expiresAt: Date.now() / 1000 + ttl, used: false });
  return { nonce, ttl };
}

function validateAndConsumeNonce(nonce: string): { valid: boolean; reason?: string } {
  if (usedNonces.has(nonce)) return { valid: false, reason: "nonce_replay" };
  const entry = nonces.get(nonce);
  if (!entry) return { valid: false, reason: "nonce_unknown" };
  if (Date.now() / 1000 > entry.expiresAt) {
    nonces.delete(nonce);
    return { valid: false, reason: "nonce_expired" };
  }
  nonces.delete(nonce);
  usedNonces.add(nonce);
  return { valid: true };
}

function canonicalHash(data: Record<string, unknown>): string {
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

router.get(
  "/.well-known/openid-credential-issuer",
  (_req, res) => {
    const issuerUrl = process.env.GAUTH_ISSUER_URL || "https://gauth.gimel.foundation";
    res.json({
      credential_issuer: issuerUrl,
      credential_endpoint: `${issuerUrl}/credentials`,
      token_endpoint: `${issuerUrl}/token`,
      credential_configurations_supported: {
        GAuthPoACredential: {
          format: "jwt_vc_json",
          scope: "gauth_poa",
          cryptographic_binding_methods_supported: ["did:key", "did:web"],
          credential_signing_alg_values_supported: ["ES256"],
          credential_definition: {
            type: ["VerifiableCredential", "GAuthPoACredential"],
          },
        },
      },
      display: [{ name: "GAuth Open Core", locale: "en-US" }],
    });
  },
);

router.post(
  "/vci/v1/offers",
  asyncHandler(async (req, res) => {
    const mandate = req.body?.mandate || {};
    const credentialType = req.body?.credential_type || "GAuthPoACredential";
    const grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    const offerId = `offer_${crypto.randomBytes(6).toString("hex")}`;
    const preAuthCode = `code_${crypto.randomBytes(24).toString("base64url")}`;

    codes.set(preAuthCode, {
      mandate,
      credentialType,
      consumed: false,
      createdAt: Date.now() / 1000,
    });

    const offer = {
      credential_issuer: process.env.GAUTH_ISSUER_URL || "https://gauth.gimel.foundation",
      credential_configuration_ids: [credentialType],
      grants: {
        [grantType]: { "pre-authorized_code": preAuthCode },
      },
    };
    offers.set(offerId, offer);
    res.status(201).json({ offer_id: offerId, ...offer });
  }),
);

router.post(
  "/vci/v1/token",
  asyncHandler(async (req, res) => {
    const preAuthCode = req.body?.["pre-authorized_code"] || "";
    const codeEntry = codes.get(preAuthCode);
    if (!codeEntry) {
      res.status(400).json({ error: "invalid_grant", error_description: "Unknown pre-authorized code" });
      return;
    }
    if (codeEntry.consumed) {
      res.status(400).json({ error: "invalid_grant", error_description: "Code already consumed" });
      return;
    }
    codeEntry.consumed = true;

    const accessToken = `tok_${crypto.randomBytes(24).toString("base64url")}`;
    const { nonce, ttl } = issueNonce();

    tokens.set(accessToken, {
      mandate: codeEntry.mandate,
      credentialType: codeEntry.credentialType,
      expiresAt: Date.now() / 1000 + TOKEN_TTL,
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL,
      c_nonce: nonce,
      c_nonce_expires_in: ttl,
    });
  }),
);

router.post(
  "/vci/v1/credentials",
  asyncHandler(async (req, res) => {
    const authHeader = req.headers.authorization || "";
    let accessToken = "";
    if (authHeader.startsWith("Bearer ")) {
      accessToken = authHeader.slice(7);
    } else {
      accessToken = req.body?.access_token || "";
    }

    const tokenEntry = tokens.get(accessToken);
    if (!tokenEntry) {
      res.status(400).json({ error: "invalid_token", error_description: "Unknown or expired access token" });
      return;
    }
    if (Date.now() / 1000 > tokenEntry.expiresAt) {
      tokens.delete(accessToken);
      res.status(400).json({ error: "invalid_token", error_description: "Access token expired" });
      return;
    }

    const cNonce = req.body?.c_nonce || "";
    if (!cNonce) {
      res.status(400).json({
        error: "invalid_proof",
        error_description: "c_nonce is required for credential issuance",
        c_nonce_error: "nonce_missing",
      });
      return;
    }
    const nonceResult = validateAndConsumeNonce(cNonce);
    if (!nonceResult.valid) {
      res.status(400).json({
        error: "invalid_proof",
        error_description: `Nonce validation failed: ${nonceResult.reason}`,
        c_nonce_error: nonceResult.reason,
      });
      return;
    }

    const mandate = tokenEntry.mandate;
    const vcId = `urn:uuid:${crypto.randomUUID()}`;
    const issuerDid = "did:web:gauth.gimel.foundation";

    const scope = (mandate.scope || {}) as Record<string, unknown>;
    const parties = (mandate.parties || {}) as Record<string, unknown>;
    const coreVerbs = (scope.core_verbs || {}) as Record<string, unknown>;

    const allowedActions = Object.entries(coreVerbs)
      .filter(([, v]) => {
        if (typeof v === "object" && v !== null) return (v as Record<string, unknown>).allowed !== false;
        return Boolean(v);
      })
      .map(([k]) => k)
      .sort();

    const vc: Record<string, unknown> = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://gauth.gimel.foundation/credentials/v1",
      ],
      id: vcId,
      type: ["VerifiableCredential", "GAuthPoACredential"],
      issuer: { id: issuerDid, name: "GAuth Open Core" },
      credentialSubject: {
        id: parties.subject ? `did:key:${parties.subject}` : "",
        mandate_id: mandate.mandate_id || "",
        governance_profile: scope.governance_profile || "",
        phase: scope.phase || "",
        allowed_actions: allowedActions,
      },
    };

    const proofValue = canonicalHash(vc);
    vc.proof = {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-rdfc-2019",
      created: new Date().toISOString(),
      verificationMethod: `${issuerDid}#key-1`,
      proofPurpose: "assertionMethod",
      proofValue,
    };

    const { nonce: newNonce, ttl: newTtl } = issueNonce();

    res.json({
      format: "jwt_vc_json",
      credential: vc,
      c_nonce: newNonce,
      c_nonce_expires_in: newTtl,
    });
  }),
);

router.post(
  "/vp/v1/presentation-requests",
  asyncHandler(async (req, res) => {
    const credentialTypes = req.body?.credential_types || ["GAuthPoACredential"];
    const purpose = req.body?.purpose || "GAuth PoA verification";

    const sessionId = `vp_${crypto.randomBytes(6).toString("hex")}`;
    const { nonce, ttl } = issueNonce(SESSION_TTL);

    vpSessions.set(sessionId, {
      status: "pending",
      nonce,
      credentialTypes,
      createdAt: Date.now() / 1000,
      expiresAt: Date.now() / 1000 + SESSION_TTL,
    });

    res.status(201).json({
      session_id: sessionId,
      presentation_definition: {
        id: `pd_${crypto.randomBytes(4).toString("hex")}`,
        input_descriptors: credentialTypes.map((ctype: string, i: number) => ({
          id: `id_${i}`,
          name: ctype,
          purpose,
          constraints: {
            fields: [
              {
                path: ["$.type"],
                filter: { type: "array", contains: { const: ctype } },
              },
            ],
          },
        })),
        format: {
          jwt_vc_json: { alg: ["ES256"] },
          jwt_vp_json: { alg: ["ES256"] },
        },
      },
      nonce,
      nonce_expires_in: ttl,
      response_uri: `/gauth/vp/v1/presentation-requests/${sessionId}/response`,
      response_mode: "direct_post",
    });
  }),
);

router.post(
  "/vp/v1/presentation-requests/:sessionId/response",
  asyncHandler(async (req, res) => {
    const sessionId = req.params.sessionId as string;
    const session = vpSessions.get(sessionId);
    if (!session) {
      res.status(400).json({ verified: false, error: "session_not_found" });
      return;
    }

    if (Date.now() / 1000 > session.expiresAt) {
      session.status = "expired";
      res.status(400).json({ verified: false, error: "session_expired" });
      return;
    }

    const nonceResult = validateAndConsumeNonce(session.nonce);
    if (!nonceResult.valid) {
      session.status = "rejected";
      res.status(400).json({
        verified: false,
        error: `nonce_${nonceResult.reason}`,
        nonce_error: nonceResult.reason,
      });
      return;
    }

    const vpToken = req.body?.vp_token;
    if (typeof vpToken === "string") {
      session.status = "rejected";
      res.status(400).json({ verified: false, error: "vp_token_must_be_vc_object" });
      return;
    }

    if (!vpToken || typeof vpToken !== "object") {
      session.status = "rejected";
      res.status(400).json({ verified: false, error: "invalid_vp_token" });
      return;
    }

    const proof = vpToken.proof;
    if (!proof || proof.type !== "DataIntegrityProof") {
      session.status = "rejected";
      res.status(400).json({ verified: false, error: "proof_verification_failed", proof_error: "No valid proof" });
      return;
    }

    const vcWithoutProof = { ...vpToken };
    delete vcWithoutProof.proof;
    const expectedHash = canonicalHash(vcWithoutProof);
    if (proof.proofValue !== expectedHash) {
      session.status = "rejected";
      res.status(400).json({ verified: false, error: "proof_verification_failed", proof_error: "Proof value mismatch" });
      return;
    }

    const vcTypes: string[] = vpToken.type || [];
    const matchedTypes = session.credentialTypes.filter((t: string) => vcTypes.includes(t));

    if (matchedTypes.length === 0) {
      session.status = "rejected";
      res.status(400).json({
        verified: false,
        error: "credential_type_mismatch",
        expected_types: session.credentialTypes,
        received_types: vcTypes,
      });
      return;
    }

    session.status = "verified";
    session.vpToken = vpToken;

    res.json({
      verified: true,
      session_id: sessionId,
      credential_types_verified: matchedTypes,
      proof_mode: "hash-integrity",
      cryptosuite: proof.cryptosuite || "ecdsa-rdfc-2019",
    });
  }),
);

router.get(
  "/vp/v1/presentation-requests/:sessionId",
  (req, res) => {
    const sessionId = req.params.sessionId as string;
    const session = vpSessions.get(sessionId);
    if (!session) {
      res.status(404).json({ error: "Session not found" });
      return;
    }
    res.json({ session_id: sessionId, status: session.status });
  },
);

router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ManagementError) {
    res.status(err.httpStatus).json({ error: { code: err.code, message: err.message } });
    return;
  }
  const message = err instanceof Error ? err.message : "Internal VCI/VP error";
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message } });
});

export default router;
