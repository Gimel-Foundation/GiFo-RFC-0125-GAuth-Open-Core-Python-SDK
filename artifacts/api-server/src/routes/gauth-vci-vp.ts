import crypto from "crypto";
import { Router, type Request, type Response, type NextFunction } from "express";
import { ManagementError } from "@workspace/db";
import {
  poaToVc,
  createDataIntegrityProof,
  verifyDataIntegrityProof,
  getVerificationPublicKey,
  BitstringStatusList,
} from "../lib/vc-crypto.js";

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
const statusList = new BitstringStatusList(1024);
const trustedIssuerKeys = new Map<string, crypto.KeyObject>();

const NONCE_TTL = 300;
const TOKEN_TTL = 3600;
const SESSION_TTL = 600;

const issuerDid = "did:web:gauth.gimel.foundation";

trustedIssuerKeys.set(issuerDid, getVerificationPublicKey());

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

function resolveIssuerKey(verificationMethod: string): crypto.KeyObject | undefined {
  const did = verificationMethod.includes("#")
    ? verificationMethod.split("#")[0]
    : verificationMethod;
  return trustedIssuerKeys.get(did);
}

function asyncHandler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res).catch(next);
  };
}

function getBaseUrl(req: Request): string {
  return process.env.GAUTH_ISSUER_URL || `${req.protocol}://${req.get("host")}`;
}

router.get(
  "/.well-known/openid-credential-issuer",
  (req, res) => {
    const baseUrl = getBaseUrl(req);
    res.json({
      credential_issuer: baseUrl,
      credential_endpoint: `${baseUrl}/gauth/vci/v1/credentials`,
      token_endpoint: `${baseUrl}/gauth/vci/v1/token`,
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
      credential_issuer: getBaseUrl(req),
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

    const statusListCredential = req.body?.status_list_credential;
    const statusListIndex = req.body?.status_list_index;

    const vc = poaToVc(mandate, issuerDid, statusListCredential, statusListIndex) as Record<string, unknown>;

    const proof = createDataIntegrityProof(vc, `${issuerDid}#key-1`);
    vc.proof = proof;

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

    const baseUrl = getBaseUrl(req);
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
      response_uri: `${baseUrl}/gauth/vp/v1/presentation-requests/${sessionId}/response`,
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

    const vpTypes: string[] = (vpToken as Record<string, unknown>).type as string[] || [];
    const isVpWrapper = vpTypes.includes("VerifiablePresentation");

    if (isVpWrapper) {
      const vpResult = verifyVpWrapper(session, vpToken as Record<string, unknown>);
      if (!vpResult.verified) {
        session.status = "rejected";
        res.status(400).json(vpResult);
        return;
      }
      session.status = "verified";
      session.vpToken = vpToken;
      res.json({ ...vpResult, session_id: sessionId });
      return;
    }

    const bareResult = verifyBareVc(session, vpToken as Record<string, unknown>);
    if (!bareResult.verified) {
      session.status = "rejected";
      res.status(400).json(bareResult);
      return;
    }
    session.status = "verified";
    session.vpToken = vpToken;
    res.json({ ...bareResult, session_id: sessionId });
  }),
);

function verifyVpWrapper(
  session: VPSession,
  vp: Record<string, unknown>,
): Record<string, unknown> {
  const vpProof = vp.proof as Record<string, unknown> | undefined;
  if (!vpProof || typeof vpProof !== "object") {
    return {
      verified: false,
      error: "proof_verification_failed",
      proof_error: "VP must include a proof",
    };
  }

  if (vpProof.challenge !== session.nonce) {
    return {
      verified: false,
      error: "proof_verification_failed",
      proof_error: "VP proof challenge must match session nonce",
    };
  }

  const holderVm = (vpProof.verificationMethod as string) || "";
  const holderKey = resolveIssuerKey(holderVm);
  const vpVerifyResult = verifyDataIntegrityProof(vp, holderKey, session.nonce);
  if (!vpVerifyResult.verified) {
    return {
      verified: false,
      error: "proof_verification_failed",
      proof_error: `VP proof invalid: ${vpVerifyResult.reason || ""}`,
    };
  }

  const vcs = vp.verifiableCredential as Record<string, unknown>[];
  if (!Array.isArray(vcs) || vcs.length === 0) {
    return { verified: false, error: "no_credentials_in_presentation" };
  }

  const allMatchedTypes: string[] = [];
  for (const vc of vcs) {
    if (!vc || typeof vc !== "object") {
      return { verified: false, error: "invalid_credential_in_presentation" };
    }

    const vcProof = vc.proof as Record<string, unknown> | undefined;
    const vm = (vcProof?.verificationMethod as string) || "";
    const resolvedKey = resolveIssuerKey(vm);
    const vcKey = resolvedKey || getVerificationPublicKey();

    const vcVerify = verifyDataIntegrityProof(vc, vcKey);
    if (!vcVerify.verified) {
      return {
        verified: false,
        error: "proof_verification_failed",
        proof_error: `VC proof invalid: ${vcVerify.reason || ""}`,
      };
    }

    if (vc.credentialStatus) {
      const revocation = statusList.checkRevocation(vc.credentialStatus as Record<string, unknown>);
      if (revocation.revoked) {
        return {
          verified: false,
          error: "credential_revoked",
          revocation_reason: revocation.reason || "",
        };
      }
    }

    const vcTypes: string[] = (vc.type as string[]) || [];
    for (const t of session.credentialTypes) {
      if (vcTypes.includes(t) && !allMatchedTypes.includes(t)) {
        allMatchedTypes.push(t);
      }
    }
  }

  if (allMatchedTypes.length === 0) {
    return {
      verified: false,
      error: "credential_type_mismatch",
      expected_types: session.credentialTypes,
    };
  }

  return {
    verified: true,
    credential_types_verified: allMatchedTypes,
    proof_mode: vpVerifyResult.mode || "",
    cryptosuite: vpVerifyResult.cryptosuite || "ecdsa-rdfc-2019",
  };
}

function verifyBareVc(
  session: VPSession,
  vc: Record<string, unknown>,
): Record<string, unknown> {
  const vcProof = vc.proof as Record<string, unknown> | undefined;
  const vm = (vcProof?.verificationMethod as string) || "";
  const resolvedKey = resolveIssuerKey(vm);
  const effectiveKey = resolvedKey || getVerificationPublicKey();

  const verificationResult = verifyDataIntegrityProof(vc, effectiveKey);
  if (!verificationResult.verified) {
    return {
      verified: false,
      error: "proof_verification_failed",
      proof_error: verificationResult.reason || "",
    };
  }

  if (vc.credentialStatus) {
    const revocation = statusList.checkRevocation(vc.credentialStatus as Record<string, unknown>);
    if (revocation.revoked) {
      return {
        verified: false,
        error: "credential_revoked",
        revocation_reason: revocation.reason || "",
      };
    }
  }

  const vcTypes: string[] = (vc.type as string[]) || [];
  const matchedTypes = session.credentialTypes.filter((t: string) => vcTypes.includes(t));

  if (matchedTypes.length === 0) {
    return {
      verified: false,
      error: "credential_type_mismatch",
      expected_types: session.credentialTypes,
      received_types: vcTypes,
    };
  }

  return {
    verified: true,
    credential_types_verified: matchedTypes,
    proof_mode: verificationResult.mode || "",
    cryptosuite: verificationResult.cryptosuite || "ecdsa-rdfc-2019",
  };
}

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
