# GAuth SDK Implementation Guide

**Version:** 1.2
**Date:** 2026-04-10
**Authors:** Gimel Foundation — Auth Team
**Audience:** SDK Teams (Python, TypeScript, Rust, Go, .NET)
**Status:** DRAFT — SDK Team Review
**License:** Mozilla Public License 2.0 (open interfaces); Gimel Technologies Terms of Service (Type C proprietary interfaces)
**Builds on:** GiFo-RFC 0116 v2.2, GiFo-RFC 0117 v1.2, GiFo-RFC 0118 v1.1, GAuth Internal Spec v1.2

---

## Abstract

This guide is the canonical reference for SDK teams implementing GAuth client libraries. It covers every adapter interface, the sealed adapter registration protocol, tariff gating, the license/ToS state machine, and the conformance test suite that every SDK must pass before certification.

The guide does not redefine the RFCs — it bridges the gap between the protocol specifications and a working SDK. Each section links back to the normative source so SDK teams can consult the full specification when needed.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Integration Patterns & Deployment Topology](#2-integration-patterns--deployment-topology)
3. [Adapter Type System](#3-adapter-type-system)
4. [Adapter Interface Reference](#4-adapter-interface-reference)
5. [Sealed Registration Protocol](#5-sealed-registration-protocol)
6. [Tariff Gating Matrix](#6-tariff-gating-matrix)
7. [License & ToS State Machine](#7-license--tos-state-machine)
8. [PEP SDK Integration](#8-pep-sdk-integration)
9. [Management API Client](#9-management-api-client)
10. [S2S Authentication](#10-s2s-authentication)
11. [Conformance Test Suite](#11-conformance-test-suite)
12. [RFC Cross-Reference Index](#12-rfc-cross-reference-index)
13. [Language-Specific Notes](#13-language-specific-notes)
14. [Open Core Exclusions](#14-open-core-exclusions)
15. [GitHub Repository Structure](#15-github-repository-structure)

---

## 1. ARCHITECTURE OVERVIEW

### 1.1 System Context

GAuth is an authorization server for AI agents implementing the P*P architecture (PAP, PEP, PDP, PIP, PVP). SDKs interact with GAuth through three protocol layers:

```
SDK Client
    │
    ├─ PEP Layer (RFC 0117)     → Enforce PoA credentials at runtime
    │     POST /gauth/pep/v1/enforce
    │     POST /gauth/pep/v1/enforce/batch
    │     POST /gauth/pep/v1/policy
    │     GET  /gauth/pep/v1/health
    │
    ├─ Management Layer (RFC 0118) → CRUD mandate lifecycle
    │     POST   /gauth/mgmt/v1/mandates
    │     POST   /gauth/mgmt/v1/mandates/:id/activate
    │     POST   /gauth/mgmt/v1/mandates/:id/revoke
    │     POST   /gauth/mgmt/v1/mandates/:id/suspend
    │     POST   /gauth/mgmt/v1/mandates/:id/resume
    │     DELETE /gauth/mgmt/v1/mandates/:id
    │     GET    /gauth/mgmt/v1/mandates/:id
    │     GET    /gauth/mgmt/v1/mandates
    │     GET    /gauth/mgmt/v1/mandates/:id/history
    │     POST   /gauth/mgmt/v1/mandates/:id/budget/increase
    │     POST   /gauth/mgmt/v1/mandates/:id/budget/consume
    │     POST   /gauth/mgmt/v1/mandates/:id/ttl/extend
    │     POST   /gauth/mgmt/v1/mandates/:id/delegate
    │     DELETE /gauth/mgmt/v1/mandates/:id/delegate/:delegationId
    │     POST   /gauth/mgmt/v1/mandates/:id/governance-profile
    │
    ├─ Connector Layer (Internal Spec §1) → Register/manage adapters
    │     POST /api/connectors/:slotName/register
    │     POST /api/connectors/:slotName/unregister
    │     POST /api/connectors/:slotName/accept-license
    │     GET  /api/connectors/status
    │     GET  /api/connectors/:slotName/health
    │
    └─ S2S Layer                 → Service-to-service authentication
          Dual-layer: Platform Key + HMAC-SHA256
```

### 1.2 Connector Slot Model

GAuth uses a 7-slot connector model. Each slot has a fixed position, a typed adapter interface, and tariff-gated availability.

| Slot | Name | Adapter Type | Interface | Mandatory |
|------|------|-------------|-----------|-----------|
| 1 | `pdp` | Internal | `PolicyDecisionAdapter` | Yes |
| 2 | `oauth_engine` | A | `OAuthEngineAdapter` | Yes |
| 3 | `foundry` | B | `FoundryAdapter` | No |
| 4 | `wallet` | B | `WalletAdapter` | No |
| 5 | `ai_governance` | C | `GovernanceAdapter` | No |
| 6 | `web3_identity` | C | `Web3IdentityAdapter` | No |
| 7 | `dna_identity` | C | `DNAIdentityAdapter` | No |

**Slot rules:**
- Slots 1 and 2 are mandatory — registration of a null adapter is rejected.
- Slots 3–4 (Type B) degrade gracefully when null: features are unavailable but the system remains operational.
- Slots 5–7 (Type C) require Ed25519 sealed manifest attestation before activation.
- Failure behavior for all adapters is **fail-closed**: if an adapter is unreachable, unhealthy, or not attested, the system denies the operation.

---

## 2. INTEGRATION PATTERNS & DEPLOYMENT TOPOLOGY

### 2.1 Overview

Organizations adopting GAuth face a deployment question: how does the GAuth authorization stack integrate with their existing infrastructure? The answer depends on whether they have an existing OAuth/OIDC stack they need to preserve, whether they run their own API gateway, or whether they are starting from scratch.

This section defines three integration patterns. Each pattern maps to a specific SDK deliverable. The adapter contract for all three patterns is defined by the RFCs — no additional specification layer is needed. The adapter is thin glue code that connects an OAuth server's extensibility mechanism to the Core SDK's APIs.

### 2.2 Sidecar Pattern — Claims Provider SDK

**Description:** The Sidecar pattern is for organizations that already have an OAuth/OIDC server in production and do not want to replace it. A claims provider SDK plugs into the existing server's extensibility mechanism and injects PoA claims into the JWT at issuance time. The SDK takes a validated mandate from the Management API (RFC 0118) and serializes it into the correct JWT claims structure per RFC 0116 §4.

```
┌─────────────────────────────────────────────────────────┐
│  Existing OAuth/OIDC Server                              │
│  (Keycloak, Azure AD, Okta, Auth0, Zitadel, etc.)       │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Claims Provider SDK (Sidecar)                     │  │
│  │                                                    │  │
│  │  1. Intercept token issuance event                 │  │
│  │  2. Fetch validated mandate (RFC 0118 Management)  │  │
│  │  3. Serialize PoA into JWT claims (RFC 0116 §4)    │  │
│  │  4. Compute scope_checksum (RFC 0116 §4.4)         │  │
│  │  5. Return enriched claims to OAuth server         │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  OAuth server issues JWT with PoA claims embedded        │
└──────────────────────┬──────────────────────────────────┘
                       │ JWT with PoA claims
                       ▼
┌─────────────────────────────────────────────────────────┐
│  PEP Middleware (Gateway or application-level)           │
│  Enforces PoA per RFC 0117 §9                            │
└─────────────────────────────────────────────────────────┘
```

**When to use:**
- The organization has an existing OAuth/OIDC deployment they cannot or do not want to replace.
- The existing server supports extensibility (protocol mappers, claims transformations, inline hooks, or Actions).
- The organization wants to add GAuth authorization as an overlay on top of their existing identity infrastructure.

**SDK deliverable:** A claims provider library that implements the `OAuthEngineAdapter` interface (§4.2) and provides provider-specific plugins for connecting to each OAuth server's extension mechanism.

**Key constraint:** The adapter contract is fully defined by RFC 0116 §8. The sidecar SDK does not define a new protocol — it translates the existing adapter interface into the OAuth server's specific extensibility API.

### 2.3 Gateway Pattern — PEP Middleware

**Description:** The Gateway pattern is for organizations that want to enforce PoA credentials at their API gateway without modifying their application code. A PEP middleware SDK sits at the gateway and evaluates incoming requests against the PoA claims carried in the JWT. This is an embeddable implementation of RFC 0117's 16-check pipeline.

```
┌─────────────────────────────────────────────────────────┐
│  Agent / Service (carrying JWT with PoA claims)          │
└──────────────────────┬──────────────────────────────────┘
                       │ Request + JWT
                       ▼
┌─────────────────────────────────────────────────────────┐
│  API Gateway (Express, Go net/http, NGINX, Envoy, etc.) │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  PEP Middleware SDK (Gateway)                      │  │
│  │                                                    │  │
│  │  1. Extract JWT from Authorization header          │  │
│  │  2. Validate credential (RFC 0116 §10.2)           │  │
│  │  3. Execute 16-check pipeline (RFC 0117 §9)        │  │
│  │  4. Return PERMIT / DENY / CONSTRAIN               │  │
│  │  5. Attach enforcement decision to request context │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
│  Gateway routes request to backend if PERMIT/CONSTRAIN   │
└──────────────────────┬──────────────────────────────────┘
                       │ Enriched request
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Backend Service (receives pre-authorized request)       │
└─────────────────────────────────────────────────────────┘
```

**When to use:**
- The organization already has an API gateway or reverse proxy.
- Enforcement should happen at the network edge, not in application code.
- The backend services should receive pre-authorized requests without needing to understand GAuth internals.

**SDK deliverable:** Framework-specific middleware libraries:
- **Express/Node.js:** `gauthPepMiddleware()` — Express middleware function
- **Go net/http:** `gauth.PEPHandler()` — Go HTTP middleware
- **NGINX/OpenResty:** Lua module for NGINX access phase
- **Envoy:** External authorization filter (ext_authz gRPC)

**Key constraint:** The PEP middleware implements the enforcement contract defined by RFC 0117 §9. The 16-check pipeline, violation codes, and decision semantics are identical regardless of the gateway framework.

### 2.4 Full Stack Pattern — Integrated Bundle

**Description:** The Full Stack pattern is for organizations starting from scratch — greenfield deployments with no existing OAuth stack to preserve. An integrated bundle pre-wires the OAuth engine (Slot 2), the Management API (RFC 0118), and the PEP (RFC 0117) into a single, turnkey deployment.

```
┌─────────────────────────────────────────────────────────┐
│  GAuth Full Stack Deployment                             │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  OAuth Engine │  │ Management   │  │    PEP       │  │
│  │  (Ory Hydra)  │  │ API          │  │  (RFC 0117)  │  │
│  │  (RFC 0116)   │  │ (RFC 0118)   │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                  │                  │          │
│         └──────────────────┼──────────────────┘          │
│                            │                             │
│                   Core SDK (shared)                      │
│                   PoA schema validation                  │
│                   JWT claims serialization               │
│                   16-check enforcement pipeline          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Agent / Service (issues, enforces, manages mandates)    │
└─────────────────────────────────────────────────────────┘
```

**When to use:**
- Greenfield deployment with no existing OAuth/OIDC server.
- The organization wants a single deployment that handles token issuance, mandate management, and enforcement.
- Development and testing environments where a complete, self-contained GAuth stack is needed.

**SDK deliverable:** A deployment bundle with:
- Pre-configured Ory Hydra as the OAuth engine (Type A adapter)
- Management API server implementing RFC 0118
- PEP service implementing RFC 0117
- Docker Compose or Helm chart for orchestration

**Key constraint:** The Full Stack bundle uses the same adapter interfaces as the Sidecar and Gateway patterns. An organization that starts with the Full Stack can later migrate to Sidecar (plugging their own OAuth server) or Gateway (deploying PEP at the edge) without changing the Core SDK.

### 2.5 OAuth Provider Compatibility Matrix

The Sidecar pattern requires provider-specific plugins. The following table maps common OAuth/OIDC providers to their extensibility mechanism and the corresponding SDK adapter:

| Provider | License | Extensibility Mechanism | Pattern Fit | SDK Adapter | Priority |
|----------|---------|------------------------|-------------|-------------|----------|
| **Ory Hydra** | Apache 2.0 | Custom consent/login handler, token hook | Full Stack (primary), Sidecar | `HydraClaimsProvider` | P0 — reference implementation |
| **Keycloak** | Apache 2.0 | Protocol mapper plugin (SPI) | Sidecar | `KeycloakProtocolMapper` | P1 — largest enterprise installed base |
| **Azure AD / Entra ID** | Proprietary (SaaS) | Claims transformation via custom policies, token issuance policies | Sidecar | `AzureADClaimsTransformer` | P2 — Microsoft-dominant enterprises |
| **Okta** | Proprietary (SaaS) | Inline hooks (token) | Sidecar | `OktaInlineHook` | P2 — SaaS-heavy organizations |
| **Auth0** | Proprietary (SaaS) | Actions (post-login, M2M credentials) | Sidecar | `Auth0Action` | P2 — SaaS-heavy organizations |
| **Zitadel** | Apache 2.0 | Actions (complement token) | Sidecar | `ZitadelAction` | P3 — emerging alternative |

**Prioritization rationale:**
- **P0 (Hydra):** Go-native, headless, highly extensible, Apache 2.0, aligns with GAuth licensing. Natural fit for the Full Stack reference deployment. Build and test the core adapter interface against Hydra first.
- **P1 (Keycloak):** Dominant in enterprise Java/Jakarta EE environments. The protocol mapper SPI is well-documented and widely used. Covers the largest single-provider segment of the enterprise market.
- **P2 (Azure AD, Okta, Auth0):** SaaS providers — the SDK ships adapter-only since you don't control the OAuth engine. These are claims enrichment adapters that inject PoA claims via the provider's hook/action mechanism.
- **P3 (Zitadel):** Newer entrant with growing adoption. Lower priority but architecturally clean.

**The SDK does not need to ship adapters for all providers on day one.** The architecture supports them via a clean adapter interface. Build the core once (the `OAuthEngineAdapter` interface from §4.2), write thin adapters per provider.

### 2.6 Adapter Interface Unification

All three integration patterns converge on the same adapter interfaces defined in the RFCs:

| Pattern | OAuth Engine (RFC 0116 §8) | PEP (RFC 0117 §9) | Management API (RFC 0118) |
|---------|---------------------------|--------------------|-----------------------------|
| **Sidecar** | Claims provider SDK implements `OAuthEngineAdapter` | External — deployed separately (Gateway or application-level) | External — calls Management API endpoints |
| **Gateway** | External — existing OAuth server issues tokens | PEP middleware implements 16-check pipeline | External — calls Management API endpoints |
| **Full Stack** | Bundled Hydra implements `OAuthEngineAdapter` | Bundled PEP service | Bundled Management API server |

**The RFCs are the interoperability guarantee.** Any adapter that produces RFC 0116-conformant tokens and validates through RFC 0118's pipeline is conformant by definition. The adapters are integration plumbing, not protocol-level components. No additional specification layer is needed beyond the three published RFCs.

---

## 3. ADAPTER TYPE SYSTEM

### 3.1 Type Classification

| Type | License | User Replaceable | Attestation | Cost |
|------|---------|-----------------|-------------|------|
| **A** — OAuth Engine | MPL 2.0 (RFC 0116 §8) | Yes — any OIDC server | No | Credits when using Gimel-hosted |
| **B** — Foundry/Wallet | MPL 2.0 (RFC 0116 §9.3) | Yes — open interface | No | Credits when using Gimel-hosted |
| **C** — Exclusive IP | Gimel Technologies ToS (proprietary) | No — Gimel-exclusive | Yes (Ed25519 manifest) | Credits + license swap |
| **D** — Billing | Internal only | No — Gimel-internal | No | Automatic |

**SDK obligation:** SDKs MUST model all four types. Type D is not directly callable by SDK consumers but the SDK must understand that billing operations are triggered automatically when Gimel-hosted adapters are active.

### 3.2 Adapter Lifecycle States

```
┌──────────┐   register()   ┌──────────────┐   satisfyAttestation()   ┌────────┐
│   null   │ ─────────────→ │   pending    │ ──────────────────────→  │ active │
└──────────┘                └──────────────┘                          └────┬───┘
     ▲                           │ (only for Type C)                       │
     │                           │                                         │
     │   unregister()            │ healthCheck() fails                     │
     └───────────────────────────┴─────────────────────────────────────────┘
                                        │
                                        ▼
                                  ┌──────────┐
                                  │  error   │
                                  └──────────┘
```

- **null**: No adapter registered. Slot falls back to `nullBehavior`.
- **pending**: Adapter registered but attestation not yet satisfied (Type C only).
- **active**: Adapter registered, attested (if required), and healthy.
- **error**: Health check failed. Automatic recovery on next successful health check.

### 3.3 Default Gimel Implementations

| Slot | Default Implementation | Label |
|------|----------------------|-------|
| `pdp` | `GAuthPDPAdapter` | GAuth PDP Engine |
| `oauth_engine` | `HydraOAuthEngineAdapter` | Ory Hydra |
| `foundry` | `GimelFoundryAdapter` | Gimel Foundry |
| `wallet` | `GimelWalletAdapter` | Gimel Wallet (OpenBao/Vault) |
| `ai_governance` | `GAgentGovernanceAdapter` | G-Agent Governance |
| `web3_identity` | `NullWeb3IdentityAdapter` | Placeholder (Phase 2) |
| `dna_identity` | `NullDNAIdentityAdapter` | Placeholder (Phase 3) |

---

## 4. ADAPTER INTERFACE REFERENCE

Each adapter interface defines a set of methods that every implementation must provide. All methods are asynchronous and return typed results. Every adapter MUST implement `healthCheck()`.

### 4.1 PolicyDecisionAdapter (Slot 1 — Internal)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** Internal Spec §1, RFC 0117 §9

```
evaluateMandate(mandate: MandatePayload, profile: GovernanceProfile) → PolicyDecision
validateCeilings(mandate: MandatePayload, profile: GovernanceProfile) → CeilingValidation
evaluateAction(action: AgentAction, mandate: MandatePayload) → ActionDecision
adjustSeverity(baseSeverity: string, profile: GovernanceProfile) → string
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `MandatePayload` | `id: string`, `clientId: string`, `scopes: string[]`, `[key: string]: unknown` |
| `GovernanceProfile` | `id: string`, `name: string`, `[key: string]: unknown` |
| `PolicyDecision` | `allowed: boolean`, `reason: string`, `violations?: string[]` |
| `CeilingValidation` | `valid: boolean`, `violations?: string[]` |
| `AgentAction` | `verb: string`, `resource: string`, `[key: string]: unknown` |
| `ActionDecision` | `allowed: boolean`, `reason: string`, `constraints?: Record<string, unknown>` |
| `AdapterHealthResult` | `healthy: boolean`, `latencyMs: number`, `details?: string` |

**SDK notes:**
- `adjustSeverity()` is synchronous — the only non-async method in any adapter.
- `evaluateMandate()` performs full mandate validation including scope, permissions, and profile matching.
- `validateCeilings()` checks the 14-attribute ceiling table (7 stateless + 7 stateful) per Internal Spec §3.2.

### 4.2 OAuthEngineAdapter (Slot 2 — Type A)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** RFC 0116 §8

```
issueToken(claims: Record<string, unknown>, options: IssuanceOptions) → SignedJWT
validateToken(token: string) → TokenValidation
revokeToken(tokenId: string, reason: string) → RevocationResult
getJWKS() → JSONWebKeySet
introspect(token: string) → IntrospectionResult
beforeTokenIssuance(context: IssuanceContext) → Record<string, unknown>
afterTokenIssuance(token: SignedJWT, context: IssuanceContext) → void
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `IssuanceOptions` | `ttl?: number`, `scopes?: string[]`, `[key: string]: unknown` |
| `SignedJWT` | `token: string`, `expiresAt: string` |
| `TokenValidation` | `valid: boolean`, `claims?: Record<string, unknown>`, `error?: string` |
| `RevocationResult` | `revoked: boolean`, `tokenId: string` |
| `JSONWebKeySet` | `keys: Record<string, unknown>[]` |
| `IntrospectionResult` | `active: boolean`, `claims?: Record<string, unknown>` |
| `IssuanceContext` | `clientId: string`, `subject: string`, `scopes: string[]`, `[key: string]: unknown` |

**SDK notes:**
- `beforeTokenIssuance()` and `afterTokenIssuance()` are lifecycle hooks. They execute in the 7-step token issuance pipeline (Validate → PDP → Billing Pre-check → Governance AI → OAuth Engine → Billing Record → Response).
- `beforeTokenIssuance()` returns additional claims to merge into the token. Return `{}` for no additions.
- The default Gimel implementation connects to Ory Hydra. User-provided implementations connect to any OIDC server (Keycloak, Auth0, Zitadel, etc.).
- `issueToken()` MUST throw on failure (fail-closed). Never return a partial or empty token.

### 4.3 FoundryAdapter (Slot 3 — Type B)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** RFC 0116 §9.3

```
executeAction(action: AgentAction, mandate: MandatePayload) → ActionResult
getAgentCatalog() → AgentCatalogEntry[]
getActionReport(actionId: string) → ActionReport
validateSandbox(agentId: string, requirements: SandboxRequirements) → SandboxValidation
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `ActionResult` | `success: boolean`, `result?: unknown`, `error?: string` |
| `AgentCatalogEntry` | `id: string`, `name: string`, `capabilities: string[]` |
| `ActionReport` | `actionId: string`, `status: string`, `result?: unknown` |
| `SandboxRequirements` | `[key: string]: unknown` |
| `SandboxValidation` | `valid: boolean`, `issues?: string[]` |

**SDK notes:**
- `executeAction()` MUST fail-closed when the connector is unavailable.
- `getAgentCatalog()` returns an empty array (not an error) when the foundry is not connected.
- Foundry and Wallet connectors use retry with exponential backoff for transient failures (max 1 retry, per slot config).

### 4.4 WalletAdapter (Slot 4 — Type B)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** RFC 0116 §9.3, §11 (EUDI compatibility)

```
storeCredential(credential: VerifiableCredential) → StorageReceipt
presentCredential(query: PresentationQuery) → VerifiablePresentation
listCredentials(filter?: CredentialFilter) → CredentialSummary[]
deleteCredential(credentialId: string) → DeletionReceipt
generateSelectiveDisclosure(credential: VerifiableCredential, disclosureFrame: SDFrame) → SDJWT
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `VerifiableCredential` | `[key: string]: unknown` |
| `StorageReceipt` | `id: string`, `stored: boolean` |
| `PresentationQuery` | `[key: string]: unknown` |
| `VerifiablePresentation` | `[key: string]: unknown` |
| `CredentialFilter` | `[key: string]: unknown` |
| `CredentialSummary` | `id: string`, `type: string`, `issuer: string` |
| `DeletionReceipt` | `id: string`, `deleted: boolean` |
| `SDFrame` | `[key: string]: unknown` |
| `SDJWT` | `token: string` |

**SDK notes:**
- `generateSelectiveDisclosure()` produces an SD-JWT from a VerifiableCredential and a disclosure frame, enabling selective attribute revelation per RFC 0116 §6.
- When the wallet slot is null, the system falls back to JWT-only token issuance (no W3C VC support).
- `storeCredential()`, `presentCredential()`, `deleteCredential()`, and `generateSelectiveDisclosure()` MUST throw when the connector is unavailable (fail-closed).
- `listCredentials()` returns an empty array (not an error) when the connector is unavailable.

### 4.5 GovernanceAdapter (Slot 5 — Type C)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** Internal Spec §1.5.1

```
checkAccess(request: GovernanceCheckRequest) → GovernanceCheckResponse
getRecommendations(context: GovernanceContext) → GovernanceRecommendation[]
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `GovernanceCheckRequest` | `requestId: string`, `operation: string`, `resource: string`, `actor: { clientId, clientType }`, `context: Record<string, unknown>` |
| `GovernanceCheckResponse` | `allowed: boolean`, `reason: string`, `recommendations?: string[]` |
| `GovernanceContext` | `[key: string]: unknown` |
| `GovernanceRecommendation` | `id: string`, `recommendation: string`, `severity: string` |

**SDK notes:**
- Type C adapter — requires Ed25519 sealed manifest attestation and Gimel Technologies ToS acceptance.
- When AI governance slot is null, the system falls back to rule-based-only evaluation (first pass only, no AI second pass).
- The internal Gimel implementation routes to G-Agent 1 (G-LLM), G-Agent 2 (G-NLP), and G-Agent 3 (Architecture Compliance).

### 4.6 Web3IdentityAdapter (Slot 6 — Type C)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** Internal Spec §1.5.2

```
resolveIdentity(identifier: string) → Web3Identity | null
verifyCredential(credential: unknown) → VerificationResult
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `Web3Identity` | `identifier: string`, `resolved: boolean`, `[key: string]: unknown` |
| `VerificationResult` | `verified: boolean`, `details?: string` |

**Status:** Phase 2 — interface defined, implementation pending.

### 4.7 DNAIdentityAdapter (Slot 7 — Type C)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** Internal Spec §1.5.3

```
resolveIdentity(identifier: string) → DNAIdentity | null
verifyBiometric(data: unknown) → VerificationResult
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `DNAIdentity` | `identifier: string`, `resolved: boolean`, `[key: string]: unknown` |

**Status:** Phase 3 — interface defined, implementation pending.

### 4.8 BillingAdapter (Type D — Internal)

**Source:** `server/integrations/connectors/types.ts`
**Normative:** Internal Spec §1.6

```
checkCredits(organizationId: string, operation: string) → CreditCheckResult
recordUsage(organizationId: string, operation: string, metadata?: Record<string, unknown>) → void
getBalance(organizationId: string) → BalanceInfo
healthCheck() → AdapterHealthResult
```

**Key types:**

| Type | Fields |
|------|--------|
| `CreditCheckResult` | `allowed: boolean`, `balance: number`, `cost: number` |
| `BalanceInfo` | `balanceCents: number`, `currency: string` |

**SDK notes:**
- Type D is not directly invoked by SDK consumers. It activates automatically when Gimel-hosted services are used.
- Gimel-hosted services are billed per usage. Invoicing details are provided separately under your service agreement.

---

## 5. SEALED REGISTRATION PROTOCOL

### 5.1 Overview

Adapter registration is "sealed" — once a Type C adapter is registered, it cannot be replaced without re-attestation. This protects Gimel's proprietary IP and ensures only certified implementations connect.

### 5.2 Registration Flow

Registration is performed programmatically via the `ConnectorSlotRegistry.register()` method. The registry enforces tariff gating and attestation requirements at registration time.

```
Caller (platform startup or admin action)
    │
    │  registry.register(slotName, adapter, implementationLabel)
    │
    │  Internal steps:
    │    1. Look up slot config from CONNECTOR_SLOT_CONFIGS
    │    2. Check tariff gate via DEPLOYMENT_POLICY_MATRIX
    │       - If availability === "null" → reject
    │    3. If Type C and attestation not yet satisfied:
    │       → Set status = "pending" (adapter stored but not active)
    │    4. Otherwise:
    │       → Set status = "active"
    │    5. Return { success: true } or { success: false, error: "..." }
    │
```

**HTTP endpoints for connector management:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/connectors/status` | Get status summary for all 7 slots |
| `GET` | `/api/connectors/:slotName/health` | Health check a specific slot |
| `GET` | `/api/connectors/:slotName/tariff-gate` | Check tariff gate for a slot |
| `POST` | `/api/connectors/:slotName/accept-license` | Accept Gimel Technologies ToS for Type C activation |

**Implementation note:** In the current release, adapter registration is performed server-side during platform initialization (see `initializeDefaultAdapters()` in `default-adapters.ts`). HTTP-based adapter registration endpoints for user-provided adapters are planned for a future release. SDKs SHOULD model the registration interface to support both programmatic and HTTP-based registration.

### 5.3 Type C Attestation — Ed25519 Sealed Manifest

Type C adapters use Ed25519 manifest signing for sealed registration. Each adapter ships with a signed manifest that proves it was built and authorized by Gimel. The GAuth runtime verifies this manifest before allowing the adapter to activate.

**Why Ed25519:** Deterministic signatures (no random nonce — same input always produces the same signature), compact keys (32-byte public key, 64-byte signature), fast verification (~75μs), and no X.509/CRL infrastructure overhead. This is simpler and more auditable than ECDSA P-256/X.509 certificate chains.

**Cryptographic parameters:**

| Parameter | Value |
|-----------|-------|
| Algorithm | Ed25519 (RFC 8032) |
| Key size | 256-bit (32-byte public key, 64-byte signature) |
| Manifest format | JSON with deterministic canonicalization (JCS — RFC 8785) |
| Key storage | HSM (production); file-based (development) |
| Max validity | 1 year from `issued_at` |

#### 5.3.1 Manifest JSON Schema

Every Type C adapter must include a signed manifest conforming to this schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://gimelfoundation.com/schemas/adapter/v1.0/manifest.json",
  "title": "GAuth Sealed Adapter Manifest",
  "type": "object",
  "required": [
    "manifest_version", "adapter_name", "adapter_type", "adapter_version",
    "slot_name", "namespace", "issued_at", "expires_at",
    "issuer", "public_key", "signature"
  ],
  "properties": {
    "manifest_version": {
      "type": "string",
      "const": "1.0",
      "description": "Manifest schema version."
    },
    "adapter_name": {
      "type": "string",
      "description": "Human-readable adapter name (e.g., 'G-Agent AI Governance')."
    },
    "adapter_type": {
      "type": "string",
      "const": "C",
      "description": "Must be 'C' for sealed adapters."
    },
    "adapter_version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$",
      "description": "Semantic version of the adapter (e.g., '1.0.0')."
    },
    "slot_name": {
      "type": "string",
      "enum": ["ai_governance", "web3_identity", "dna_identity"],
      "description": "Target connector slot. Must match the slot being registered."
    },
    "namespace": {
      "type": "string",
      "pattern": "^@gimel/",
      "description": "Package namespace. Must start with '@gimel/' for trusted adapters."
    },
    "issued_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp when the manifest was signed."
    },
    "expires_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 expiration. Max 1 year from issued_at."
    },
    "issuer": {
      "type": "string",
      "const": "gimel-foundation",
      "description": "Signing authority. Must be 'gimel-foundation'."
    },
    "capabilities": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Adapter capability declarations (e.g., ['governance.analyze', 'governance.threat_detect'])."
    },
    "checksum": {
      "type": "string",
      "description": "SHA-256 hash of the adapter binary/bundle for integrity verification."
    },
    "public_key": {
      "type": "string",
      "description": "Hex-encoded Ed25519 public key used to verify the signature."
    },
    "signature": {
      "type": "string",
      "description": "Hex-encoded Ed25519 signature over the canonicalized manifest (excluding the 'signature' field)."
    }
  }
}
```

**Example manifest:**

```json
{
  "manifest_version": "1.0",
  "adapter_name": "G-Agent AI Governance",
  "adapter_type": "C",
  "adapter_version": "1.0.0",
  "slot_name": "ai_governance",
  "namespace": "@gimel/ai-governance",
  "issued_at": "2026-04-09T00:00:00Z",
  "expires_at": "2027-04-09T00:00:00Z",
  "issuer": "gimel-foundation",
  "capabilities": [
    "governance.analyze_authority",
    "governance.assess_threat",
    "governance.check_compliance"
  ],
  "checksum": "sha256:a1b2c3d4e5f6...",
  "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7e8c3...",
  "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522..."
}
```

#### 5.3.2 Signing Procedure (Gimel Build Pipeline)

```
1. Build the Type C adapter binary/bundle
2. Compute SHA-256 checksum of the binary
3. Construct manifest JSON with all fields EXCEPT "signature"
4. Canonicalize the manifest using JCS (RFC 8785):
   - Sort object keys lexicographically
   - Remove insignificant whitespace
   - Normalize Unicode (NFC)
5. Sign the canonicalized bytes with Gimel's Ed25519 private key:
   signature = Ed25519_Sign(private_key, canonical_bytes)
6. Insert the hex-encoded signature into the manifest
7. Bundle the manifest with the adapter
```

#### 5.3.3 Verification Algorithm (GAuth Runtime)

When a Type C adapter registers with the GAuth runtime:

```
1. Parse the adapter manifest JSON
2. Schema validation:
   a. Verify manifest_version == "1.0"
   b. Verify adapter_type == "C"
   c. Verify slot_name matches the requested connector slot
   d. Verify namespace starts with "@gimel/" (trusted namespace rule)
   e. Verify issuer == "gimel-foundation"
3. Temporal validation:
   a. Verify issued_at <= current_time
   b. Verify expires_at > current_time
   c. Verify expires_at - issued_at <= 365 days
4. Signature verification:
   a. Extract the "signature" field and remove it from the manifest
   b. Canonicalize the remaining manifest using JCS (RFC 8785)
   c. Verify: Ed25519_Verify(public_key, canonical_bytes, signature)
5. Revocation check:
   a. Check the manifest's public_key against the revoked-keys list
   b. Check the adapter_version against the revoked-versions list
6. Binary integrity (optional but RECOMMENDED):
   a. Compute SHA-256 of the loaded adapter binary
   b. Verify it matches the manifest's checksum field
7. If all pass → adapter attested, status = "active"
8. If any fail → registration rejected, status unchanged, event logged
```

#### 5.3.4 Trusted Namespace Rules

| Rule | Description |
|------|-------------|
| `@gimel/*` namespace required | All Type C adapter manifests MUST declare a namespace starting with `@gimel/`. Manifests with any other namespace are rejected. |
| Namespace-slot binding | Each slot has a canonical namespace: `@gimel/ai-governance`, `@gimel/web3-identity`, `@gimel/dna-identity`. Cross-slot registration is rejected. |
| Collision prevention | The runtime rejects manifests where `namespace` + `adapter_version` matches an already-registered adapter unless the existing adapter is being explicitly replaced (requires admin authority). |
| Spoofing rejection | Manifests claiming `@gimel/*` but signed with an unknown public key are rejected. Only keys in the Gimel trusted key set are accepted. |

#### 5.3.5 Gimel Trusted Key Set

The GAuth runtime embeds Gimel's Ed25519 public keys for manifest verification:

| Key ID | Purpose | Rotation |
|--------|---------|----------|
| `gimel-prod-v1` | Production adapter signing | Annual renewal, 30-day overlap |
| `gimel-dev-v1` | Development/staging adapter signing | Annual renewal |

**Key distribution:** Public keys are embedded in the GAuth runtime binary and also published at `https://gimelfoundation.com/.well-known/adapter-keys.json`. The runtime uses embedded keys by default; the remote endpoint is used for key rotation during the overlap period.

**Key rotation:** When rotating keys, both the old and new key are valid during the overlap period. After the overlap, the old key is added to the revoked-keys list.

#### 5.3.6 Revocation

| Mechanism | Speed | Use Case |
|-----------|-------|----------|
| Revoked-keys list | Immediate (in-memory lookup) | Compromised signing key |
| Revoked-versions list | Immediate (in-memory lookup) | Vulnerable adapter version |
| Manifest expiry | Automatic (temporal check) | Standard lifecycle |

The GAuth runtime maintains in-memory revocation lists, refreshed from `https://gimelfoundation.com/.well-known/adapter-revocations.json` on a configurable interval (default: 5 minutes).

**Fail-closed:** Manifest verification failure for any reason (parse error, bad signature, expired manifest, revoked key, untrusted namespace) results in rejection. No fallback or degraded mode.

**Current implementation status:** The Ed25519 manifest verification protocol is fully specified above. The current runtime implementation uses `satisfyAttestation(slotName)` as a programmatic flag (boolean state transition) that is called when license acceptance is confirmed via `POST /api/connectors/:slotName/accept-license`. SDK implementations SHOULD build the full Ed25519 manifest verification pipeline now; the flag-based fallback will be removed once all Type C adapters ship with signed manifests.

### 5.4 Registration Without Attestation (Type A/B)

Type A and Type B adapters do not require attestation. The registration flow is:

1. Validate S2S authentication
2. Check tariff gate
3. Verify slot is not mandatory (cannot unregister mandatory slots)
4. Register adapter directly → `status = "active"`

### 5.5 Unregistration

```
POST /api/connectors/:slotName/unregister
```

- Mandatory slots (`pdp`, `oauth_engine`) cannot be unregistered.
- Unregistration resets the slot to `null` status with `implementationLabel = "None"`.
- Health check history is cleared.

### 5.6 Attestation Satisfaction Endpoint

```
POST /api/connectors/:slotName/accept-license
```

For Type C slots, this endpoint:
1. Verifies the caller has admin authority
2. Records license acceptance (`license_type`, `license_accepted_at`, `license_version`)
3. Calls `satisfyAttestation()` on the registry
4. Transitions slot status from `pending` → `active`

---

## 6. TARIFF GATING MATRIX

### 6.1 Tariff Codes

| Code | Name | Description |
|------|------|-------------|
| **O** | Open Core | Self-hosted only. No Gimel services. Rule-based PEP enforcement only. |
| **S** | Small | Entry paid tier. Selected Gimel-hosted services. |
| **M** | Medium | Full platform. AI governance, all Type A+B+selected C. |
| **L** | Large | Enterprise. All adapter types. Priority support. |

> **Note:** Tariff code `G` exists for internal Gimel team use only (beta testing, M-equivalent with auto-replenish billing). It is **not part of the public SDK surface**. SDK implementations MUST NOT expose Tariff G to third-party consumers. The G→M equivalence logic is handled server-side by GAuth and is transparent to SDKs — if a G-tariff user calls the SDK, the server resolves it to M-equivalent behavior automatically.

**Open Core design principle:** Tariff O provides the full PEP enforcement pipeline (all 16 checks per RFC 0117 §9.1) using **rule-based evaluation only**. AI-powered governance (G-Agent 1, G-Agent 2, G-Agent 3) is not available at this tier — the `ai_governance` slot is always `null`. This means the system operates without an AI second pass: every review (permissions, restrictions, threats) is evaluated by rules alone. This is by design — Open Core users get production-grade authorization without any dependency on Gimel-hosted AI services.

### 6.2 Deployment Policy Matrix

This matrix defines adapter availability per tariff per adapter type. SDK implementations MUST enforce these gates.

**Type A/B/C — Connector Slot Matrix:**

| Slot | Type | O | S | M | L |
|------|------|---|---|---|---|
| `pdp` | Internal | active_always | active_always | active_always | active_always |
| `oauth_engine` | A | user_provided_required | gimel_or_user | gimel_or_user | gimel_or_user |
| `foundry` | B | null_or_user | gimel_or_user | gimel_or_user | gimel_or_user |
| `wallet` | B | null_or_user | gimel_or_user | gimel_or_user | gimel_or_user |
| `ai_governance` | C | null | null | attested_gimel | attested_gimel |
| `web3_identity` | C | null | null | null_or_attested_gimel | attested_gimel |
| `dna_identity` | C | null | null | null | attested_gimel |

**Type D — Billing Adapter Availability:**

| Tariff | Billing Adapter State | Trigger | Billing Behavior |
|--------|----------------------|---------|-----------------|
| **O** | Inactive (null) | No Gimel-hosted services used | No platform charges. User runs self-hosted only. |
| **S** | Auto-active | Activates when any Gimel-hosted Type A or B adapter is registered | Metered billing. Credits consumed per operation. |
| **M** | Auto-active | Always active (full platform) | Metered billing. Credits consumed per operation. |
| **L** | Auto-active | Always active (enterprise) | Metered billing. Credits consumed per operation. Priority support. |

The Billing adapter (Type D) is **never directly registered or controlled by SDK consumers**. It activates automatically based on Gimel-hosted service usage. Billing terms are governed by your service agreement.

### 6.3 Availability Code Semantics

| Code | Meaning | SDK Behavior |
|------|---------|-------------|
| `active_always` | Always active. Gimel-managed. | Slot cannot be null. Always available. |
| `gimel_or_user` | Gimel default or user-provided. | Accept either Gimel or user adapter. |
| `user_provided_required` | User must provide their own. | Reject Gimel adapter registration. Require user-provided. |
| `null_or_user` | Null (features unavailable) or user-provided. | Accept user adapter or null. |
| `attested_gimel` | Requires Ed25519 sealed manifest attestation. Gimel-only. | Reject until attestation satisfied. |
| `null_or_attested_gimel` | Null fallback until attested. | Accept null or attested Gimel adapter. |
| `null` | Slot not available for this tariff. | Reject all registration attempts. |

### 6.4 Tariff Gate Check Algorithm

```
function checkTariffGate(slotName, tariff):
    matrix = DEPLOYMENT_POLICY_MATRIX[slotName]
    availability = matrix[tariff]

    if availability == "null":
        return { allowed: false, reason: "Slot not available for tariff" }

    if adapterType == "C" and (effectiveTariff == "O" or effectiveTariff == "S"):
        return { allowed: false, reason: "Type C requires tariff M or higher" }

    switch availability:
        case "active_always":
            return { allowed: true, provenance: "gimel_managed" }
        case "gimel_or_user":
            return { allowed: true, provenance: "gimel_or_user" }
        case "user_provided_required":
            return { allowed: true, provenance: "user_must_provide" }
        case "null_or_user":
            return { allowed: true, provenance: "user_optional" }
        case "attested_gimel":
            if attestationRequired and not attestationSatisfied:
                return { allowed: false, reason: "Attestation required" }
            return { allowed: true, provenance: "attested_gimel" }
        case "null_or_attested_gimel":
            if attestationRequired and not attestationSatisfied:
                return { allowed: true, provenance: "null_fallback_until_attested" }
            return { allowed: true, provenance: "attested_gimel" }
```

---

## 7. LICENSE & ToS STATE MACHINE

### 7.1 Two-Tier ToS Model

GAuth uses a two-tier Terms of Service model:

| Tier | Name | Scope | When Required |
|------|------|-------|--------------|
| **Tier 1** | Platform ToS | Covers all GAuth platform usage. Applies to all customers using any Gimel-hosted service (Type A, B, or C). | First activation of any Gimel-hosted adapter |
| **Tier 2** | Proprietary Service ToS | Per-service proprietary terms. Covers specific Type C adapters (AI Governance, Web3 Identity, DNA Identity). | Activation of each specific Type C adapter |

**Activation gate:** A customer must accept Platform ToS (Tier 1) before any Gimel-hosted service activation, AND accept the relevant Proprietary Service ToS (Tier 2) before each Type C adapter activation.

### 7.2 License States

Every customer has a license state that determines which adapter types they can access.

| Field | Type | Values |
|-------|------|--------|
| `license_type` | string | `"mpl_2_0"` (default) or `"gimel_tos"` |
| `license_accepted_at` | timestamp | When Platform ToS was accepted (null if not accepted) |
| `license_version` | string | Version of Platform ToS accepted (e.g., `"2026.1"`) |

Per-service acceptance is tracked independently per Type C slot:

| Field | Scope | Values |
|-------|-------|--------|
| `service_tos_accepted` | Per slot (ai_governance, web3_identity, dna_identity) | `true` / `false` |
| `service_tos_version` | Per slot | Version of per-service ToS accepted |
| `service_tos_accepted_at` | Per slot | Timestamp of acceptance |

### 7.3 State Machine

```
┌──────────────────────────────────────────┐
│  license_type: mpl_2_0                    │
│  (default — new customer)                 │
│                                           │
│  Access: Self-hosted only (no Gimel services) │
│  No Type A/B/C Gimel-hosted adapters      │
└──────────┬────────────────────────────────┘
           │
           │ User activates any Gimel-hosted service
           │ (Hydra, Foundry, Wallet, or Type C)
           ▼
┌──────────────────────────────────────────┐
│  Tier 1: Platform ToS Gate                │
│                                           │
│  "Using Gimel-hosted services requires    │
│   acceptance of the Gimel Platform Terms  │
│   of Service."                            │
│                                           │
│  [ Cancel ]  [ Accept Platform ToS ]      │
└──────────┬────────────────────────────────┘
           │ User accepts
           ▼
┌──────────────────────────────────────────┐
│  license_type: gimel_tos                  │
│  license_accepted_at: <now>               │
│  license_version: "2026.1"                │
│                                           │
│  Access: Type A, B (Gimel-hosted)         │
│  Billing adapter (D) active               │
└──────────┬────────────────────────────────┘
           │
           │ User requests Type C feature
           │ (AI governance, Web3, DNA)
           ▼
┌──────────────────────────────────────────┐
│  Tier 2: Proprietary Service ToS Gate     │
│  (per-service — must accept for EACH      │
│   Type C adapter individually)            │
│                                           │
│  "Activating [AI Governance] requires     │
│   acceptance of the Gimel Proprietary     │
│   Service Terms for this service."        │
│                                           │
│  [ Cancel ]  [ Accept Service ToS ]       │
└──────────┬────────────────────────────────┘
           │ User accepts
           ▼
┌──────────────────────────────────────────┐
│  Type C adapter activated for this slot    │
│  service_tos_accepted: true               │
│  service_tos_version: "2026.1"            │
│                                           │
│  Access: Type A, B, C (for accepted slots)│
│  Ed25519 manifest attestation still required│
└──────────────────────────────────────────┘
```

### 7.4 ToS Version Updates and Re-Acceptance

When Gimel publishes a new version of either ToS tier:

| Scenario | Behavior |
|----------|----------|
| Platform ToS version bump | All customers with `license_version` < new version are prompted for re-acceptance on next Gimel-hosted operation. Operations are blocked (fail-closed) until re-accepted. |
| Proprietary Service ToS version bump | Customers with `service_tos_version` < new version for the affected slot are prompted for re-acceptance. The specific Type C adapter is suspended until re-accepted. |

**Re-acceptance triggers:**
- Attempt to use a Gimel-hosted adapter after Platform ToS version bump
- Attempt to use a Type C adapter after its Proprietary Service ToS version bump
- New `accept-license` call with updated `license_version` / `service_tos_version`

### 7.5 Key Rules

- Platform ToS (Tier 1) is **per-customer**. Accepted once, applies to all Gimel-hosted services.
- Proprietary Service ToS (Tier 2) is **per-customer, per-service**. Each Type C adapter requires separate acceptance.
- The transition from `mpl_2_0` → `gimel_tos` is one-way in practice (no downgrade path while Gimel-hosted adapters are active).
- When any Gimel-hosted service is activated, the Billing adapter (Type D) automatically becomes active.
- ToS version bumps require re-acceptance before continued use (fail-closed).

### 7.6 SDK Implementation Requirements

SDKs MUST:

1. Check `license_type` before attempting any Gimel-hosted adapter operation.
2. If `license_type === "mpl_2_0"` and the user requests a Gimel-hosted service, prompt for Platform ToS acceptance (Tier 1).
3. For Type C features, additionally check per-service ToS acceptance and prompt if not accepted (Tier 2).
4. Call `POST /api/connectors/:slotName/accept-license` with `{ license_version, service_tos_version }` to record acceptance.
5. On ToS version bump detection, block operations and prompt for re-acceptance.
6. Only proceed with adapter registration after both applicable tiers are accepted.

---

## 8. PEP SDK INTEGRATION

### 8.1 EnforcementRequest Schema

**Normative:** RFC 0117 §4.1
**JSON Schema URI:** `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-request.json`

SDKs MUST construct enforcement requests conforming to this schema:

```json
{
  "request_id": "unique-correlation-id",
  "timestamp": "2026-04-09T10:00:00Z",
  "action": {
    "verb": "urn:gauth:verb:core:file:modify",
    "resource": "src/app/main.ts",
    "resource_type": "file",
    "parameters": { "amount_cents": 5 },
    "sector": "541511",
    "region": "DE",
    "transaction_type": "standard",
    "decision_type": "autonomous"
  },
  "agent": {
    "agent_id": "agent_456",
    "service": "codeshield",
    "session_id": "sess_789"
  },
  "credential": {
    "format": "jwt",
    "token": "<JWT string>",
    "mandate_id": "mdt_abc123"
  },
  "context": {
    "session_state": {
      "tool_calls_used": 42,
      "lines_committed": 150,
      "session_started_at": "2026-04-09T09:00:00Z",
      "session_cost_cents": 210
    }
  }
}
```

**Action verb format:** `urn:gauth:verb:{domain}:{category}:{action}`

### 8.2 EnforcementDecision Schema

**Normative:** RFC 0117 §5.1
**JSON Schema URI:** `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-decision.json`

```json
{
  "request_id": "unique-correlation-id",
  "decision": "PERMIT",
  "timestamp": "2026-04-09T10:00:01Z",
  "enforcement_mode": "stateless",
  "checks": [
    {
      "check_id": "CHK-01",
      "check_name": "Credential Integrity",
      "result": "pass",
      "duration_ms": 0.5
    }
  ],
  "enforced_constraints": [],
  "violations": [],
  "audit": {
    "processing_time_ms": 2.3,
    "pep_version": "1.2.0",
    "pep_interface_version": "1.2",
    "checks_performed": 16,
    "checks_passed": 16,
    "checks_failed": 0
  }
}
```

**Decision semantics:**

| Decision | Meaning | SDK Action |
|----------|---------|------------|
| `PERMIT` | All checks passed. | Proceed with the action. |
| `DENY` | One or more checks failed with error severity. | Block the action. Inspect `violations`. |
| `CONSTRAIN` | Permitted with restrictions. | Proceed but respect `enforced_constraints`. |

**Decision precedence:** Any `fail` with `severity: "error"` → DENY. Warnings do not affect the decision.

### 8.3 16-Check Evaluation Pipeline

SDKs implementing a local PEP MUST execute checks in this canonical order:

| Order | Check ID | Name | PoA Fields | Violation Codes |
|-------|----------|------|-----------|----------------|
| 1 | CHK-01 | Credential Integrity | signature, schema_version, scope_checksum | `CREDENTIAL_INVALID` |
| 2 | CHK-02 | Temporal & Status | exp, nbf, iat, aud, mandate_status, sub | `CREDENTIAL_EXPIRED`, `CREDENTIAL_REVOKED`, `CREDENTIAL_SUPERSEDED`, `AGENT_MISMATCH` |
| 3 | CHK-03 | Governance Profile Ceiling | governance_profile + ceiling table | `PROFILE_CEILING_EXCEEDED` |
| 4 | CHK-04 | Phase | phase | `PHASE_MISMATCH` |
| 5 | CHK-05 | Sector | allowed_sectors | `SECTOR_MISMATCH` |
| 6 | CHK-06 | Region | allowed_regions | `REGION_MISMATCH` |
| 7 | CHK-07 | Path Validation | allowed_paths, denied_paths | `PATH_DENIED`, `PATH_NOT_ALLOWED` |
| 8 | CHK-08 | Verb Permission | core_verbs | `VERB_NOT_ALLOWED` |
| 9 | CHK-09 | Verb Constraints | per-verb constraints | `CONSTRAINT_VIOLATED` |
| 10 | CHK-10 | Platform Permissions | Layer 3 permissions | `PLATFORM_PERMISSION_DENIED` |
| 11 | CHK-11 | Transaction Type & Matrix | allowed_transactions, transaction_matrix | `TRANSACTION_NOT_ALLOWED` |
| 12 | CHK-12 | Decision Type | allowed_decisions | `DECISION_NOT_ALLOWED` |
| 13 | CHK-13 | Budget | remaining_cents, amount_cents | `BUDGET_EXCEEDED`, `BUDGET_EXHAUSTED` |
| 14 | CHK-14 | Session Limits | max_tool_calls, max_session_duration, max_lines_per_commit | `SESSION_LIMIT_EXCEEDED` |
| 15 | CHK-15 | Approval | approval_mode | `APPROVAL_REQUIRED` |
| 16 | CHK-16 | Delegation Chain | delegation_chain, max_depth | `DELEGATION_DEPTH_EXCEEDED`, `DELEGATION_SCOPE_EXCEEDED` |

### 8.4 Enforcement Modes

| Mode | Description | Latency Target | When Used |
|------|-------------|---------------|-----------|
| **Stateless** | Validates from token claims only. Fails fast on first DENY. | < 5ms | Read-only actions, low-risk operations |
| **Stateful** | Validates against live mandate state (DB lookup). Collects all violations before returning. | < 100ms | Write operations, budget-consuming actions |

**Mode selection:** Automatic based on action characteristics per Internal Spec §10.4.

### 8.5 Delegation Chain Enforcement (CHK-16)

CHK-16 implements two-pass scope narrowing:

1. **Pass 1 — Chain integrity:** Validate delegation chain integrity, depth, and temporal validity.
2. **Pass 2 — Scope narrowing:** Compute `effectiveScope` by intersecting each delegation entry's `scopeRestriction` with the parent PoA. Re-evaluate CHK-05, CHK-06, CHK-07, CHK-08, CHK-11, CHK-12 against the narrowed scope.

**DelegationChainEntry:**

```
delegator: string
delegate: string
scopeRestriction?: {
    sectors?: string[]
    regions?: string[]
    allowedActions?: string[]
    allowedTransactions?: string[]
    allowedDecisions?: string[]
    allowedPaths?: string[]
    deniedPaths?: string[]
}
delegatedAt: string
maxDepthRemaining?: number
```

### 8.6 HTTP Binding

| Method | Path | Request | Response |
|--------|------|---------|----------|
| `POST` | `/gauth/pep/v1/enforce` | `EnforcementRequest` | `EnforcementDecision` or `EnforcementError` |
| `POST` | `/gauth/pep/v1/enforce/batch` | `{ requests, mode }` | `BatchDecision` |
| `POST` | `/gauth/pep/v1/policy` | `{ credential }` | `EnforcementPolicy` |
| `GET` | `/gauth/pep/v1/health` | — | `{ status, pep_version, interface_version }` |

**All three decisions (PERMIT, DENY, CONSTRAIN) return HTTP 200.** HTTP 4xx/5xx are reserved for PEP operational errors. SDKs MUST inspect the `decision` field in the response body.

### 8.7 Error Response Schema

**JSON Schema URI:** `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-error.json`

| Error Code | HTTP Status | Meaning |
|-----------|-------------|---------|
| `INVALID_REQUEST` | 400 | Malformed enforcement request |
| `CREDENTIAL_PARSE_ERROR` | 400 | Cannot parse credential |
| `ISSUER_UNREACHABLE` | 502 | Stateful enforcement failed — issuer not reachable |
| `EVALUATION_TIMEOUT` | 504 | Pipeline exceeded timeout |
| `PEP_INTERNAL_ERROR` | 500 | Unexpected internal error |

**Fail-closed:** Callers MUST treat error responses as equivalent to DENY.

---

## 9. MANAGEMENT API CLIENT

### 9.1 Mandate Lifecycle

**Normative:** RFC 0118 §4

| Operation | Method | Path | Input | Output |
|-----------|--------|------|-------|--------|
| Create | `POST` | `/gauth/mgmt/v1/mandates` | `MandateCreationRequest` | `MandateCreationResponse` |
| Activate | `POST` | `/gauth/mgmt/v1/mandates/:id/activate` | `MandateActivationRequest` | `MandateActivationResponse` |
| Revoke | `POST` | `/gauth/mgmt/v1/mandates/:id/revoke` | `MandateRevocationRequest` | `MandateRevocationResponse` |
| Suspend | `POST` | `/gauth/mgmt/v1/mandates/:id/suspend` | `MandateSuspensionRequest` | `MandateSuspensionResponse` |
| Resume | `POST` | `/gauth/mgmt/v1/mandates/:id/resume` | `MandateResumptionRequest` | `MandateResumptionResponse` |
| Delete | `DELETE` | `/gauth/mgmt/v1/mandates/:id` | `deleted_by` | `DeletionConfirmation` |

### 9.2 Mandate Lifecycle States

```
DRAFT → ACTIVE → SUSPENDED → ACTIVE (resume)
                           → REVOKED (terminal)
              → REVOKED (terminal)
              → EXPIRED (terminal, automatic)
              → BUDGET_EXCEEDED (terminal, automatic)
              → SUPERSEDED (terminal, automatic)
```

| State | Terminal | PEP Behavior |
|-------|----------|-------------|
| `DRAFT` | No | Not enforceable |
| `ACTIVE` | No | Enforceable |
| `SUSPENDED` | No | Rejected on CHK-02 |
| `EXPIRED` | Yes | Rejected on CHK-02 |
| `REVOKED` | Yes | Rejected on CHK-02 |
| `BUDGET_EXCEEDED` | Yes | Rejected on CHK-13 |
| `SUPERSEDED` | Yes | Rejected on CHK-02 |

### 9.3 Mutability Rules

| State | Scope | Budget Ceiling | TTL | Status |
|-------|-------|----------------|-----|--------|
| `DRAFT` | Mutable | Mutable | Mutable | → ACTIVE only |
| `ACTIVE` | **Immutable** | Additive-only (increase, never decrease) | Additive-only (extend, never shorten) | → SUSPENDED, terminal |
| `SUSPENDED` | **Immutable** | Additive-only | Additive-only | → ACTIVE, REVOKED, EXPIRED |
| Terminal | Immutable | Frozen | Frozen | Frozen |

### 9.4 Budget Operations

**Normative:** RFC 0118 §7

| Operation | Method | Path | Key Fields |
|-----------|--------|------|-----------|
| Increase ceiling | `POST` | `.../budget/increase` | `additional_cents`, `increased_by`, `reason` |
| Report consumption | `POST` | `.../budget/consume` | `deducted_cents`, `enforcement_request_id`, `operation_type` |
| Extend TTL | `POST` | `.../ttl/extend` | `additional_seconds`, `extended_by`, `reason` |

**Budget rules:**
- `additional_cents` MUST be > 0.
- Ceiling can only increase (additive-only). Never decrease.
- Consumption reports MUST include `enforcement_request_id` for idempotency.
- Duplicate `enforcement_request_id` returns `accepted: false` (no double-deduction).
- Budget deduction MUST be atomic. Concurrent consumption reports are serialized.
- When `remaining_cents` reaches zero → mandate transitions to `BUDGET_EXCEEDED`.

### 9.5 Supersession Atomicity

When `activateMandate()` detects an existing ACTIVE mandate for the same `(agent_id, project_id)` pair:

1. Supersede the existing mandate (→ SUPERSEDED)
2. Activate the new mandate (→ ACTIVE)
3. Both transitions MUST be atomic (single transaction)

At no point may two mandates be simultaneously ACTIVE for the same `(agent_id, project_id)` pair.

### 9.6 Validation Pipeline

**Normative:** RFC 0118 §10

Every mandate passes a three-stage validation pipeline before acceptance:

1. **Schema validation** — Against RFC 0116 §4.3 canonical PoA JSON Schema
2. **Ceiling enforcement** — Against RFC 0115 governance profile ceilings (14 attributes × 5 profiles)
3. **Consistency checks** — 6 deterministic rules:
   - Rule 1: `approval_mode` consistency with governance profile minimum
   - Rule 2: `ttl_seconds` within profile ceiling
   - Rule 3: Budget ceiling within profile limits
   - Rule 4: Session limits within profile ceilings
   - Rule 5: Delegation depth within profile maximum
   - Rule 6: `allowed_paths` / `denied_paths` mutual exclusivity check

---

## 10. S2S AUTHENTICATION

### 10.1 Dual-Layer Model

All GAuth S2S communication uses a mandatory two-layer authentication model:

| Layer | Purpose | Header | Value |
|-------|---------|--------|-------|
| 1 — Platform Identity | Identifies the calling service as a Gimel platform member | `X-GAuth-Platform-Key` | Shared `GIMEL_PLATFORM_KEY` |
| 2 — Payload Integrity | Proves payload has not been tampered with | `X-GAuth-HMAC-Signature` | `HMAC-SHA256(payload, service_secret)` |

### 10.2 HMAC Computation

```
signature = HMAC-SHA256(
    key = <per-service webhook secret>,
    message = JSON.stringify(request_body)
)
header = "sha256=" + hex(signature)
```

**Per-service secrets:**

| Service | Secret Environment Variable |
|---------|-----------------------------|
| Foundry | `FOUNDRY_WEBHOOK_SECRET` |
| G-Agent | `GAGENT_WEBHOOK_SECRET` |
| Billing | `BILLING_WEBHOOK_SECRET` |
| Wallet | `WALLET_AUTH_SHARED_SECRET` |

### 10.3 SDK Implementation

SDKs MUST provide an S2S client that:

1. Automatically attaches both headers to every S2S request.
2. Rejects responses that fail HMAC verification (fail-closed).
3. Never logs or exposes secret key material.

---

## 11. CONFORMANCE TEST SUITE

Every SDK MUST pass all conformance tests before certification. Tests are organized by category with unique vector IDs.

### 11.1 Adapter Registration Tests

#### CT-REG-001: Register Type A adapter (OAuth Engine)
- **Input:** Register `HydraOAuthEngineAdapter` to slot `oauth_engine`, tariff `M`
- **Expected:** `{ success: true }`, slot status = `active`

#### CT-REG-002: Register Type B adapter (Foundry)
- **Input:** Register `GimelFoundryAdapter` to slot `foundry`, tariff `S`
- **Expected:** `{ success: true }`, slot status = `active`

#### CT-REG-003: Register Type C adapter without attestation
- **Input:** Register `GAgentGovernanceAdapter` to slot `ai_governance`, tariff `M`, no attestation
- **Expected:** `{ success: true }`, slot status = `pending` (not `active`)

#### CT-REG-004: Register Type C adapter with attestation
- **Input:** Register to slot `ai_governance`, tariff `M`, then call `satisfyAttestation("ai_governance")`
- **Expected:** slot status transitions from `pending` → `active`

#### CT-REG-005: Tariff gate blocks Type C for tariff S
- **Input:** Register to slot `ai_governance`, tariff `S`
- **Expected:** tariff gate returns `{ allowed: false }`, availability = `null`

#### CT-REG-006: Tariff gate blocks Type C for tariff O
- **Input:** Register to slot `ai_governance`, tariff `O`
- **Expected:** tariff gate returns `{ allowed: false }`, availability = `null`

#### CT-REG-007: Tariff M enables Type C slot
- **Input:** `checkTariffGate("ai_governance", "M")`
- **Expected:** availability = `attested_gimel`, `{ allowed: true }` (after attestation)

#### CT-REG-008: Unregister mandatory slot rejected
- **Input:** `unregister("pdp")`
- **Expected:** `{ success: false, error: "Cannot unregister pdp — it is mandatory" }`

#### CT-REG-009: Unregister optional slot succeeds
- **Input:** `unregister("foundry")` (after registration)
- **Expected:** `{ success: true }`, slot status = `null`, implementationLabel = `"None"`

#### CT-REG-010: DNA Identity blocked for tariff M (requires L)
- **Input:** `checkTariffGate("dna_identity", "M")`
- **Expected:** availability = `null`, `{ allowed: false }`

#### CT-REG-011: Valid Ed25519 manifest accepted
- **Input:** Type C adapter with valid signed manifest (correct namespace `@gimel/ai-governance`, valid signature, valid temporal window, issuer `gimel-foundation`, public key in trusted key set)
- **Expected:** Manifest verification passes, slot status transitions to `active`

#### CT-REG-012: Tampered manifest rejected (bad signature)
- **Input:** Type C adapter with manifest where `adapter_version` has been modified after signing (signature does not match canonicalized content)
- **Expected:** Ed25519 signature verification fails, registration rejected, event logged

#### CT-REG-013: Wrong signing key rejected
- **Input:** Type C adapter with manifest signed by an Ed25519 key NOT in the Gimel trusted key set
- **Expected:** Public key not found in trusted key set, registration rejected, event logged

#### CT-REG-014: Untrusted namespace rejected
- **Input:** Type C adapter with manifest `namespace: "@evil/ai-governance"` (does not start with `@gimel/`)
- **Expected:** Namespace validation fails, registration rejected before signature verification

#### CT-REG-015: Expired manifest rejected
- **Input:** Type C adapter with manifest where `expires_at` < current_time
- **Expected:** Temporal validation fails, registration rejected

#### CT-REG-016: Slot name mismatch rejected
- **Input:** Type C adapter with manifest `slot_name: "web3_identity"` attempting to register to slot `ai_governance`
- **Expected:** Slot name validation fails, registration rejected

#### CT-REG-017: Revoked key rejected
- **Input:** Type C adapter with valid manifest signed by a key that has been added to the revoked-keys list
- **Expected:** Revocation check fails, registration rejected even though signature is cryptographically valid

#### CT-REG-018: Manifest validity exceeds 1 year rejected
- **Input:** Type C adapter with manifest where `expires_at - issued_at > 365 days`
- **Expected:** Temporal validation fails (max validity exceeded), registration rejected

### 11.2 PEP Enforcement Tests

#### CT-PEP-001: PERMIT — all checks pass
- **Input:** Valid mandate, valid credential, verb in `core_verbs`, resource in `allowed_paths`, sufficient budget
- **Expected:** `decision: "PERMIT"`, 16 checks all `pass`, no violations

#### CT-PEP-002: DENY — expired credential (CHK-02)
- **Input:** Credential with `exp` < current_time
- **Expected:** `decision: "DENY"`, CHK-02 `fail`, violation code `CREDENTIAL_EXPIRED`

#### CT-PEP-003: DENY — revoked mandate (CHK-02, stateful)
- **Input:** Mandate with status `REVOKED`, stateful mode
- **Expected:** `decision: "DENY"`, CHK-02 `fail`, violation code `CREDENTIAL_REVOKED`

#### CT-PEP-004: DENY — verb not allowed (CHK-08)
- **Input:** Action verb `urn:gauth:verb:core:deployment:deploy`, verb not in `core_verbs`
- **Expected:** `decision: "DENY"`, CHK-08 `fail`, violation code `VERB_NOT_ALLOWED`

#### CT-PEP-005: DENY — path denied (CHK-07)
- **Input:** Resource `.env`, `denied_paths: [".env", "secrets/"]`
- **Expected:** `decision: "DENY"`, CHK-07 `fail`, violation code `PATH_DENIED`

#### CT-PEP-006: DENY — path not in allowed set (CHK-07)
- **Input:** Resource `config/database.yml`, `allowed_paths: ["src/", "tests/"]`
- **Expected:** `decision: "DENY"`, CHK-07 `fail`, violation code `PATH_NOT_ALLOWED`

#### CT-PEP-007: Denied paths take precedence over allowed paths (CHK-07)
- **Input:** Resource `src/.env`, `allowed_paths: ["src/"]`, `denied_paths: [".env"]`
- **Expected:** `decision: "DENY"`, violation code `PATH_DENIED`

#### CT-PEP-008: DENY — budget exceeded (CHK-13)
- **Input:** `remaining_cents: 100`, `action.parameters.amount_cents: 200`
- **Expected:** `decision: "DENY"`, CHK-13 `fail`, violation code `BUDGET_EXCEEDED`

#### CT-PEP-009: DENY — budget exhausted (CHK-13)
- **Input:** `remaining_cents: 0`
- **Expected:** `decision: "DENY"`, CHK-13 `fail`, violation code `BUDGET_EXHAUSTED`

#### CT-PEP-010: DENY — sector mismatch (CHK-05)
- **Input:** `action.sector: "621111"`, `allowed_sectors: ["541511", "541512"]`
- **Expected:** `decision: "DENY"`, CHK-05 `fail`, violation code `SECTOR_MISMATCH`

#### CT-PEP-011: DENY — region mismatch (CHK-06)
- **Input:** `action.region: "US"`, `allowed_regions: ["DE", "EU"]`
- **Expected:** `decision: "DENY"`, CHK-06 `fail`, violation code `REGION_MISMATCH`

#### CT-PEP-012: PASS — region supranational resolution (CHK-06)
- **Input:** `action.region: "DE"`, `allowed_regions: ["EU"]`
- **Expected:** CHK-06 `pass` (DE is an EU member)

#### CT-PEP-013: DENY — phase mismatch (CHK-04)
- **Input:** Deployment action, `phase: "plan"` (plan phase is read-only)
- **Expected:** `decision: "DENY"`, CHK-04 `fail`, violation code `PHASE_MISMATCH`

#### CT-PEP-014: DENY — session limit exceeded (CHK-14)
- **Input:** `session_state.tool_calls_used: 501`, `max_tool_calls: 500`
- **Expected:** `decision: "DENY"`, CHK-14 `fail`, violation code `SESSION_LIMIT_EXCEEDED`

#### CT-PEP-015: Stateless mode — fail fast on first DENY
- **Input:** Credential expired AND verb not allowed (two violations)
- **Expected:** `decision: "DENY"`, only CHK-02 executed (fail-fast), CHK-08 skipped

#### CT-PEP-016: Stateful mode — collect all violations
- **Input:** Credential expired AND verb not allowed (two violations), stateful mode
- **Expected:** `decision: "DENY"`, both CHK-02 and CHK-08 executed, both violations reported

#### CT-PEP-017: DENY — delegation depth exceeded (CHK-16)
- **Input:** Delegation chain with 4 entries, `max_depth: 3`
- **Expected:** `decision: "DENY"`, CHK-16 `fail`, violation code `DELEGATION_DEPTH_EXCEEDED`

#### CT-PEP-018: DENY — delegation scope exceeded (CHK-16)
- **Input:** Delegated scope includes `urn:gauth:verb:core:deployment:deploy`, parent scope does not
- **Expected:** `decision: "DENY"`, CHK-16 `fail`, violation code `DELEGATION_SCOPE_EXCEEDED`

#### CT-PEP-019: CHK-11 — transaction matrix cross-product
- **Input:** `action.verb: "urn:gauth:verb:core:file:modify"`, `action.transaction_type: "high_value"`, transaction_matrix entry `{ verb: "file:modify", transaction_type: "high_value", allowed: false }`
- **Expected:** `decision: "DENY"`, CHK-11 `fail`, violation code `TRANSACTION_NOT_ALLOWED`

#### CT-PEP-020: CHK-11 — verb-specific entry takes precedence over type-only
- **Input:** transaction_matrix has both `{ transaction_type: "standard", allowed: true }` and `{ verb: "file:delete", transaction_type: "standard", allowed: false }`, action verb is `file:delete`
- **Expected:** `decision: "DENY"` (verb-specific entry wins)

#### CT-PEP-021: Error response — fail-closed
- **Input:** Send enforcement request with malformed credential JSON
- **Expected:** HTTP 400, `error_code: "CREDENTIAL_PARSE_ERROR"`, SDK treats as DENY

#### CT-PEP-022: DENY — governance profile ceiling exceeded (CHK-03)
- **Input:** Action targets production deployment, governance_profile = `standard` (ceiling: dev, staging only)
- **Expected:** `decision: "DENY"`, CHK-03 `fail`, violation code `PROFILE_CEILING_EXCEEDED`

#### CT-PEP-023: DENY — verb constraint violated (CHK-09)
- **Input:** `verb: "urn:gauth:verb:core:file:modify"`, verb constraint `maxFileSizeBytes: 1048576`, action parameter `file_size: 5242880`
- **Expected:** `decision: "DENY"`, CHK-09 `fail`, violation code `CONSTRAINT_VIOLATED`

#### CT-PEP-024: DENY — platform permission denied (CHK-10)
- **Input:** Action requires `shell.execute` platform permission, agent lacks it in `platform_permissions`
- **Expected:** `decision: "DENY"`, CHK-10 `fail`, violation code `PLATFORM_PERMISSION_DENIED`

#### CT-PEP-025: DENY — decision type not allowed (CHK-12)
- **Input:** `action.decision_type: "autonomous"`, PoA `allowed_decisions: ["supervised", "four-eyes"]`
- **Expected:** `decision: "DENY"`, CHK-12 `fail`, violation code `DECISION_NOT_ALLOWED`

#### CT-PEP-026: DENY — approval required (CHK-15)
- **Input:** `approval_mode: "supervised"`, action requires approval, no approval record present
- **Expected:** `decision: "DENY"`, CHK-15 `fail`, violation code `APPROVAL_REQUIRED`

#### CT-PEP-027: CONSTRAIN — path restriction applied
- **Input:** Valid mandate with `allowed_paths: ["src/"]`, action targets `src/components/Button.tsx`
- **Expected:** `decision: "CONSTRAIN"`, enforced_constraints include path boundary

#### CT-PEP-028: Batch enforce — all_or_nothing mode
- **Input:** Two enforcement requests, first PERMIT, second DENY, mode = `all_or_nothing`
- **Expected:** `overall_decision: "DENY"`, both individual decisions returned

#### CT-PEP-029: Batch enforce — independent mode
- **Input:** Two enforcement requests, first PERMIT, second DENY, mode = `independent`
- **Expected:** `overall_decision: "DENY"`, first decision = PERMIT, second = DENY

#### CT-PEP-030: Sector wildcard pass (CHK-05)
- **Input:** `action.sector: "541511"`, PoA `allowed_sectors: ["*"]`
- **Expected:** CHK-05 `pass` (wildcard matches all sectors)

#### CT-PEP-031: Region wildcard pass (CHK-06)
- **Input:** `action.region: "US"`, PoA `allowed_regions: ["global"]`
- **Expected:** CHK-06 `pass` (wildcard matches all regions)

### 11.3 Management API Tests

#### CT-MGMT-001: Create mandate in DRAFT
- **Input:** Valid `MandateCreationRequest` with governance_profile `standard`, budget 10000 cents
- **Expected:** `mandate_id` returned, `status: "DRAFT"`, scope_checksum computed

#### CT-MGMT-002: Activate mandate (DRAFT → ACTIVE)
- **Input:** `activateMandate(mandate_id)` for a valid DRAFT mandate
- **Expected:** `status: "ACTIVE"`, `activated_at` set, `expires_at` = `activated_at + ttl_seconds`

#### CT-MGMT-003: Revoke active mandate (ACTIVE → REVOKED)
- **Input:** `revokeMandate(mandate_id, revoked_by, reason)`
- **Expected:** `status: "REVOKED"`, terminal, cascade to child delegations

#### CT-MGMT-004: Suspend active mandate (ACTIVE → SUSPENDED)
- **Input:** `suspendMandate(mandate_id, suspended_by, reason)`
- **Expected:** `status: "SUSPENDED"`, PEP rejects on CHK-02

#### CT-MGMT-005: Resume suspended mandate (SUSPENDED → ACTIVE)
- **Input:** `resumeMandate(mandate_id, resumed_by, reason)` while TTL not expired
- **Expected:** `status: "ACTIVE"`, `remaining_ttl_seconds` computed

#### CT-MGMT-006: Resume rejected — TTL expired during suspension
- **Input:** `resumeMandate()` where `activated_at + ttl_seconds < current_time`
- **Expected:** Error `MANDATE_EXPIRED`, mandate transitions to EXPIRED

#### CT-MGMT-007: Delete DRAFT mandate
- **Input:** `deleteMandate(mandate_id, deleted_by)` for DRAFT mandate
- **Expected:** Mandate removed, audit record retained

#### CT-MGMT-008: Delete non-DRAFT rejected
- **Input:** `deleteMandate()` for ACTIVE mandate
- **Expected:** Error — only DRAFT mandates can be deleted

#### CT-MGMT-009: Budget increase (additive-only)
- **Input:** `increaseBudget(mandate_id, additional_cents: 5000)`
- **Expected:** `total_cents` increased by 5000, `remaining_cents` increased by 5000

#### CT-MGMT-010: Budget decrease rejected
- **Input:** Attempt to set `total_cents` lower than current value
- **Expected:** Error — budget ceiling can only increase

#### CT-MGMT-011: Budget consumption with idempotency
- **Input:** Two `reportConsumption()` calls with same `enforcement_request_id`
- **Expected:** First call: `accepted: true`, budget deducted. Second call: `accepted: false`, budget unchanged.

#### CT-MGMT-012: Budget exhaustion triggers state transition
- **Input:** `reportConsumption()` reducing `remaining_cents` to 0
- **Expected:** Mandate transitions to `BUDGET_EXCEEDED` (terminal)

#### CT-MGMT-013: Supersession atomicity
- **Input:** Create and activate mandate M1 for (agent_A, project_X). Then create and activate mandate M2 for same pair.
- **Expected:** M1 transitions to `SUPERSEDED`, M2 is `ACTIVE`. At no point are both ACTIVE simultaneously.

#### CT-MGMT-014: TTL extension (additive-only)
- **Input:** `extendTTL(mandate_id, additional_seconds: 3600)`
- **Expected:** `expires_at` extended by 3600 seconds. Cannot shorten TTL.

#### CT-MGMT-015: Ceiling enforcement rejects over-limit mandate
- **Input:** Create mandate with `governance_profile: "standard"`, `max_tool_calls: 1000` (ceiling is 500)
- **Expected:** Validation error — ceiling violation for `max_tool_calls`

#### CT-MGMT-016: Scope immutability on ACTIVE mandate
- **Input:** Attempt to modify `core_verbs` on an ACTIVE mandate
- **Expected:** Error — scope is immutable once ACTIVE

#### CT-MGMT-017: Cascade revocation through delegation chain
- **Input:** Revoke parent mandate that has child delegations
- **Expected:** All child mandates also transitioned to REVOKED

#### CT-MGMT-018: Suspend cascade through delegation chain
- **Input:** Suspend parent mandate with children
- **Expected:** All children also SUSPENDED

#### CT-MGMT-019: Query mandate by ID
- **Input:** `getMandate(mandate_id)` for existing ACTIVE mandate
- **Expected:** Full `MandateDetail` returned with scope, budget, delegation_chain, timestamps

#### CT-MGMT-020: List mandates with filter
- **Input:** `listMandates({ filter: { customer_id, status: ["ACTIVE"] }, pagination: { limit: 10 } })`
- **Expected:** Paginated response with matching mandates and `has_more` flag

#### CT-MGMT-021: Get mandate history (audit trail)
- **Input:** `getMandateHistory(mandate_id)` for mandate that has been created, activated, budget consumed
- **Expected:** Ordered event list with `CREATE`, `ACTIVATE`, `BUDGET_CONSUMPTION` events

#### CT-MGMT-022: TTL shortening rejected
- **Input:** Attempt to set `expires_at` earlier than current value
- **Expected:** Error — TTL can only be extended (additive-only)

#### CT-MGMT-023: Revoke from SUSPENDED state
- **Input:** `revokeMandate()` for SUSPENDED mandate
- **Expected:** `status: "REVOKED"` — suspended mandates can be revoked directly

#### CT-MGMT-024: Terminal state transition rejected
- **Input:** Attempt `resumeMandate()` on REVOKED mandate
- **Expected:** Error — terminal states are irreversible

#### CT-MGMT-025: Delegation creation with scope narrowing
- **Input:** Create delegation with `scopeRestriction` narrower than parent mandate scope
- **Expected:** Delegation created, child scope is intersection of parent and restriction

#### CT-MGMT-026: Delegation rejected — scope exceeds parent
- **Input:** Create delegation granting verbs not in parent mandate `core_verbs`
- **Expected:** Error — delegated scope cannot exceed delegator's scope

### 11.4 License & Attestation Tests

#### CT-LIC-001: Default license is mpl_2_0
- **Input:** New customer record
- **Expected:** `license_type: "mpl_2_0"`, `license_accepted_at: null`

#### CT-LIC-002: License switch on Type C activation
- **Input:** Customer with `license_type: "mpl_2_0"` calls `accept-license` for `ai_governance`
- **Expected:** `license_type: "gimel_tos"`, `license_accepted_at` set, `license_version: "2026.1"`

#### CT-LIC-003: Type C registration blocked without license
- **Input:** Customer with `license_type: "mpl_2_0"` attempts Type C adapter registration
- **Expected:** Registration blocked, prompt for ToS acceptance

#### CT-LIC-004: Attestation satisfaction transitions pending → active
- **Input:** Type C adapter in `pending` status, call `satisfyAttestation(slotName)`
- **Expected:** `attestationSatisfied: true`, `status: "active"`

#### CT-LIC-005: Attestation on non-Type-C slot rejected
- **Input:** `satisfyAttestation("foundry")` (Type B, no attestation required)
- **Expected:** `{ success: false, error: "Slot foundry does not require attestation" }`

#### CT-LIC-006: Platform ToS required before Gimel-hosted service
- **Input:** Customer with `license_type: "mpl_2_0"` attempts to use Gimel-hosted Hydra
- **Expected:** Operation blocked, prompt for Platform ToS acceptance (Tier 1)

#### CT-LIC-007: Proprietary Service ToS required per Type C slot
- **Input:** Customer with Platform ToS accepted, attempts `ai_governance` without service ToS
- **Expected:** Adapter activation blocked, prompt for Proprietary Service ToS (Tier 2)

#### CT-LIC-008: ToS version bump triggers re-acceptance
- **Input:** Customer accepted `license_version: "2026.1"`, new version `"2026.2"` published
- **Expected:** Next Gimel-hosted operation blocked until re-acceptance with new version

#### CT-LIC-009: Service ToS independence across slots
- **Input:** Customer accepts service ToS for `ai_governance` but not `web3_identity`
- **Expected:** `ai_governance` accessible, `web3_identity` still blocked

### 11.5 S2S Authentication Tests

#### CT-S2S-001: Valid dual-layer auth accepted
- **Input:** Request with valid `X-GAuth-Platform-Key` and valid `X-GAuth-HMAC-Signature`
- **Expected:** Request processed normally

#### CT-S2S-002: Missing platform key rejected
- **Input:** Request without `X-GAuth-Platform-Key` header
- **Expected:** HTTP 401

#### CT-S2S-003: Invalid HMAC rejected
- **Input:** Request with valid platform key but tampered payload (HMAC mismatch)
- **Expected:** HTTP 401

#### CT-S2S-004: HMAC with wrong service secret rejected
- **Input:** Request signed with Foundry secret sent to Billing endpoint
- **Expected:** HTTP 401

---

## 12. RFC CROSS-REFERENCE INDEX

| SDK Feature | RFC 0115 | RFC 0116 | RFC 0117 | RFC 0118 | Internal Spec |
|-------------|----------|----------|----------|----------|---------------|
| **Three-layer capability model** | §3 (action verbs, permissions, vendor capabilities) | — | — | — | — |
| **Governance profile definitions** | §4 (5 profiles: minimal, standard, strict, enterprise, behörde) | — | — | §9 (assignment) | §3 (ceiling table) |
| **Governance profile ceilings** | §4.2 (14 attributes × 5 profiles) | — | §9.2 CHK-03 (ceiling enforcement) | §4.3 (ceiling validation) | §3.1 (ceiling values) |
| **Authority delegation matrix** | §5 (multi-agent verb/permission isolation) | — | §9.2 CHK-16 (chain validation) | §8 (delegation CRUD) | — |
| **Structured scope model** | §6 (NAICS sectors, ISO 3166-1 regions) | — | §9.2 CHK-05/06 (sector/region) | — | — |
| **Vollmacht (PoA) schema** | §2 (conceptual schema) | §4 (PoA token schema) | — | — | — |
| **Token format & claims** | — | §4 (PoA Schema), §5 (JWT), §6 (SD-JWT), §7 (W3C VC) | — | — | §1.6.5 (billing claims) |
| **OAuth Engine adapter** | — | §8 (Type A interface) | — | — | §1.3 (Hydra detail) |
| **Foundry/Wallet adapters** | — | §9.3 (Type B interface) | — | — | §1.4 (module detail) |
| **Type C adapters** | — | — | — | — | §1.5 (proprietary) |
| **Attestation protocol** | — | — | — | — | §2 (Ed25519 manifest) |
| **PEP enforcement** | — | §10.2 (validation modes) | §4-8 (interface contract), §9 (eval pipeline) | — | — |
| **16-check pipeline** | — | — | §9.1 (canonical order), §9.2 (check specs) | — | — |
| **Violation codes** | — | — | §5.3 (22 codes) | — | — |
| **PEP HTTP binding** | — | — | §8 (endpoints, status codes, headers) | — | — |
| **Mandate CRUD** | — | — | — | §4 (lifecycle) | — |
| **Status transitions** | — | — | — | §6 (state machine, supersession) | — |
| **Budget operations** | — | — | — | §7 (increase, consume, TTL) | — |
| **Delegation lifecycle** | §5 (A2A policies) | — | §11 (chain enforcement) | §8 (delegation CRUD) | — |
| **Tariff model** | — | — | — | — | §4 (O/S/M/L) |
| **Connector slots** | — | — | — | — | §1.1 (7-slot model) |
| **Tariff gating** | — | — | — | — | §4.2 (feature matrix) |
| **License/ToS** | — | — | — | — | §1.5.4 (license switch) |
| **S2S auth** | — | — | — | — | §6 (dual-layer) |
| **Billing model** | — | — | — | — | §1.6.4 (per-usage metering) |
| **Scope checksum** | — | §4.4 (computation) | §9.2 CHK-01 (verification) | §10 (validation) | — |
| **Verb namespace** | §3.1 (action verb taxonomy) | — | §4.2 (URN format) | — | — |
| **Error schemas** | — | §12.2 (token errors) | §6 (PEP errors) | §12 (mgmt errors) | — |
| **Integration patterns** | — | §8 (OAuth adapter) | §13 (deployment patterns) | — | — |

---

## 13. LANGUAGE-SPECIFIC NOTES

### 13.1 Common Patterns

All SDKs MUST implement:

1. **Client builder** — Fluent API for constructing a GAuth client with base URL, credentials, and options.
2. **Typed request/response models** — Generated from the JSON Schemas referenced in this guide.
3. **Error hierarchy** — Separate error types for PEP errors, Management API errors, S2S errors, and network errors.
4. **Retry with exponential backoff** — For transient failures (HTTP 502, 504). Max 1 retry for Foundry/Wallet (Type B). No retry for PEP decisions (they are deterministic).
5. **Health check client** — Wrappers for `/gauth/pep/v1/health` and per-slot health endpoints.

### 13.2 Python SDK

- Use `dataclasses` or Pydantic v2 models for all request/response types.
- Async support via `asyncio` + `httpx`.
- HMAC computation: `hmac.new(key, msg, hashlib.sha256)`.
- Ed25519 verification: `cryptography` library (`Ed25519PublicKey.verify()`).
- JSON canonicalization: `canonicaljson` or `json-canonicalization` package (JCS / RFC 8785).
- Package name: `gauth-sdk`.

### 13.3 TypeScript SDK

- Use Zod schemas for runtime validation (align with `drizzle-zod` patterns used in GAuth server).
- Async support: native `Promise` / `async-await`.
- HMAC computation: `crypto.createHmac('sha256', key)`.
- Ed25519 verification: Node.js `crypto.verify('ed25519', ...)` or `@noble/ed25519`.
- JSON canonicalization: `canonicalize` package (JCS / RFC 8785).
- Package name: `@gauth/sdk`.

### 13.4 Rust SDK

- Use `serde` for serialization/deserialization of all request/response types.
- Async support: `tokio` + `reqwest`.
- HMAC computation: `hmac` + `sha2` crates.
- Ed25519 verification: `ed25519-dalek` crate.
- JSON canonicalization: `serde_json` with sorted keys or `json-canon` crate (JCS / RFC 8785).
- Package name: `gauth-sdk`.
- All adapter traits should use `async_trait`.

### 13.5 Go SDK

- Use struct types with JSON tags for all request/response types.
- HMAC computation: `crypto/hmac` + `crypto/sha256`.
- Ed25519 verification: `crypto/ed25519` (standard library).
- JSON canonicalization: `github.com/nicktrav/canonicaljson` or manual sorted-key serialization (JCS / RFC 8785).
- HTTP client: `net/http` with context-aware timeouts.
- Module path: `github.com/gimelfoundation/gauth-sdk-go`.

### 13.6 .NET SDK

- Use record types for immutable request/response models.
- Async support: `Task<T>` / `async-await`.
- HMAC computation: `System.Security.Cryptography.HMACSHA256`.
- Ed25519 verification: `System.Security.Cryptography.Ed25519` (.NET 9+) or `NSec.Cryptography`.
- JSON canonicalization: `JsonCanonicalization` NuGet package (JCS / RFC 8785).
- Package name: `GAuth.Sdk`.
- Target: .NET 8+.

---

## 14. OPEN CORE EXCLUSIONS

### 14.1 Overview

GAuth Open Core is licensed under the Mozilla Public License 2.0 (MPL 2.0) with Gimel Foundation Additional Terms. The open-source license covers the full PEP enforcement pipeline (all 16 checks), the Management API, the adapter registration framework, and all Type A and Type B adapter interfaces.

Three capabilities are **excluded** from the open-source license. These are proprietary to the Gimel Foundation, available only via Type C sealed adapters under the Gimel Technologies Terms of Service, and protected by Ed25519 manifest attestation.

### 14.2 Exclusion Table

| # | Exclusion | Slot | Adapter Interface | Tariff Availability | Phase |
|---|-----------|------|-------------------|---------------------|-------|
| 1 | **AI-Enabled Governance** | 5 (`ai_governance`) | `GovernanceAdapter` | M, L | Available |
| 2 | **Web3 Identity Integration** | 6 (`web3_identity`) | `Web3IdentityAdapter` | M (null or attested), L | Phase 2 |
| 3 | **DNA-Based Identities / PQC** | 7 (`dna_identity`) | `DNAIdentityAdapter` | L only | Phase 3 |

### 14.3 What Open Core Includes Without Exclusions

Open Core (Tariff O) provides:

- **Full 16-check PEP enforcement pipeline** — all checks per RFC 0117 §9.1 using rule-based evaluation only
- **Complete Management API** — mandate lifecycle, budget operations, delegation, governance profile assignment
- **Type A adapter interface** — bring your own OIDC provider (Keycloak, Auth0, Zitadel, etc.)
- **Type B adapter interfaces** — bring your own Foundry and Wallet implementations
- **Adapter registration framework** — the full 7-slot connector model with tariff gating
- **Conformance test suite** — all test vectors for verifying SDK correctness

The system is **fully functional** for production use without the excluded capabilities. AI-Enabled Governance adds an AI second-pass review; without it, all evaluations are rule-based. Web3 and DNA identity extend the identity model; without them, standard identity resolution is used.

### 14.4 License Boundary

| Component | License | Modifiable | Redistributable |
|-----------|---------|------------|-----------------|
| SDK source code (all languages) | MPL 2.0 | Yes (file-level copyleft) | Yes |
| Type A/B adapter interfaces | MPL 2.0 | Yes | Yes |
| PEP engine, Management API | MPL 2.0 | Yes | Yes |
| Conformance test suite | MPL 2.0 | Yes | Yes |
| Type C adapter implementations | Gimel Technologies ToS (proprietary) | No | No |
| Type C adapter *interfaces* (method signatures) | MPL 2.0 | Yes | Yes |
| Ed25519 manifest verification code | MPL 2.0 | Yes | Yes |

**Important distinction:** The Type C adapter *interfaces* (the method signatures in §4.5, §4.6, §4.7) are open-source under MPL 2.0. Only the Gimel *implementations* of those interfaces are proprietary. The SDK includes the interface definitions so that the system can correctly handle the `null` / `pending` / `active` lifecycle for Type C slots, even when no proprietary adapter is installed.

**MPL 2.0 copyleft obligation:** File-level copyleft means: if you modify an MPL 2.0-licensed file, your modifications to that file must also be made available under MPL 2.0. However, proprietary code in separate files can freely use, import, and link against MPL 2.0 code without copyleft applying to the proprietary files. This makes MPL 2.0 a "weak copyleft" — stronger than permissive licenses (MIT, Apache 2.0) but weaker than strong copyleft (GPL).

### 14.5 Gimel Foundation Additional Terms

The following additional terms apply on top of the MPL 2.0 base license:

1. **AI-Enabled Governance Exclusion** — Third parties may not create, distribute, or offer competing implementations of AI-powered governance evaluation for the GAuth adapter slot system without a separate commercial license from the Gimel Foundation.
2. **Web3 Identity Integration Exclusion** — Third parties may not create, distribute, or offer competing implementations of Web3/blockchain-based identity resolution for the GAuth adapter slot system without a separate commercial license.
3. **DNA-Based Identity / PQC Exclusion** — Third parties may not create, distribute, or offer competing implementations of DNA-based identity verification or post-quantum cryptographic identity for the GAuth adapter slot system without a separate commercial license.

These exclusions apply only to the specific adapter slot interfaces (slots 5, 6, 7). They do not restrict any other use, modification, or redistribution of the open-source components.

---

## 15. GITHUB REPOSITORY STRUCTURE

### 15.1 Repository Layout

Each SDK language SHOULD be published as a separate GitHub repository under the Gimel Foundation organization. All repositories MUST follow a consistent structure:

```
gauth-sdk-{lang}/
├── README.md                ← Landing page: what GAuth is, quick-start, badges
├── LICENSE                  ← MPL 2.0 full text
├── ADDITIONAL-TERMS.md      ← Gimel Foundation Additional Terms (three exclusions)
├── CONTRIBUTING.md          ← Contribution guidelines, CLA reference
├── SECURITY.md              ← Security policy, vulnerability reporting
├── docs/
│   ├── architecture.md      ← System context, P*P model, 7-slot adapter diagram
│   ├── quick-start.md       ← 5-minute getting started guide
│   ├── pep-integration.md   ← PEP enforcement guide with code examples
│   ├── mgmt-api.md          ← Management API client guide
│   ├── adapters.md          ← Adapter type system, how to provide your own Type A/B
│   ├── conformance.md       ← How to run the conformance test suite
│   └── exclusions.md        ← Detailed explanation of the three proprietary exclusions
├── src/                     ← SDK source code
├── tests/                   ← Conformance test suite (CT-REG, CT-PEP, CT-MGMT, CT-LIC, CT-S2S)
└── examples/                ← Working code examples
    ├── basic-enforcement/   ← Minimal PEP enforce call
    ├── mandate-lifecycle/   ← Create → activate → consume → revoke flow
    └── custom-adapter/      ← Bring-your-own Type A OAuth adapter
```

### 15.2 README.md Requirements

Every SDK repository README MUST include:

1. **One-paragraph description** — What GAuth Open Core is and what problem it solves
2. **"What's in the box" summary** — Table listing all modules/packages in the SDK
3. **Architecture diagram** — Text-based or linked image showing the P*P layers and adapter slots
4. **Quick-start code snippet** — Minimal working example (5–10 lines) showing how to enforce an action
5. **Installation instructions** — Package manager commands for the target language
6. **License notice** — MPL 2.0 with explicit reference to ADDITIONAL-TERMS.md
7. **Exclusions notice** — Short paragraph stating that three capabilities are excluded from the open-source license, with a link to the full exclusions document
8. **Badges** — License badge, CI status, SDK version, conformance test status
9. **Links** — To the full SDK Implementation Guide, RFC specifications, and Gimel Foundation website

### 15.3 README Quick-Start Example (Python)

```python
from gauth_core import GAuthClient

client = GAuthClient(base_url="https://gauth.example.com")

decision = client.pep.enforce(
    credential=my_poa_token,
    action={"verb": "urn:gauth:verb:core:file:modify", "resource": "src/main.ts"},
    agent={"agent_id": "agent_456", "session_id": "sess_789"},
)

if decision.decision == "PERMIT":
    proceed()
elif decision.decision == "CONSTRAIN":
    proceed_with(decision.enforced_constraints)
else:
    block(decision.violations)
```

### 15.4 README Quick-Start Example (TypeScript)

```typescript
import { GAuthClient } from "@gauth/sdk";

const client = new GAuthClient({ baseUrl: "https://gauth.example.com" });

const decision = await client.pep.enforce({
  credential: myPoaToken,
  action: { verb: "urn:gauth:verb:core:file:modify", resource: "src/main.ts" },
  agent: { agentId: "agent_456", sessionId: "sess_789" },
});

if (decision.decision === "PERMIT") {
  proceed();
} else if (decision.decision === "CONSTRAIN") {
  proceedWith(decision.enforcedConstraints);
} else {
  block(decision.violations);
}
```

### 15.5 License and Exclusions Notice Template

Every README MUST include a notice section at the bottom:

```markdown
## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE) with
[Gimel Foundation Additional Terms](ADDITIONAL-TERMS.md).

### Open Core Exclusions

Three capabilities are excluded from the open-source license and are available
only under the Gimel Technologies Terms of Service:

1. **AI-Enabled Governance** (Slot 5)
2. **Web3 Identity Integration** (Slot 6)
3. **DNA-Based Identities / PQC** (Slot 7)

The full PEP enforcement pipeline (16 checks), Management API, and all Type A/B
adapter interfaces are fully open-source. See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md)
for details.
```

### 15.6 Legal Framework

GAuth Open Core is governed by a layered legal structure involving two entities:

**Gimel Foundation gGmbH i.G.** — The foundation publishes the GiFo-RFCs and the open-source project. The Gimel Foundation Legal Terms apply to all use of GAuth, whether Open Core or proprietary.

**Gimel Technologies** — The commercial entity that operates proprietary services. When a user chooses to use proprietary services (including the Excluded Components), a **license swap** occurs: the user moves from the open-source MPL 2.0 license to the Gimel Technologies Terms of Service. This swap is described in §7 (License & ToS State Machine) as the transition from `license_type: "mpl_2_0"` to `license_type: "gimel_tos"`.

The license structure for SDK repositories:

| Layer | Scope | Governing Terms |
|-------|-------|-----------------|
| **Gimel Foundation Legal Terms** | All use of GAuth (Open Core and proprietary) | Apply universally |
| **MPL 2.0** | Open Core components only | Governs source code rights for Open Core |
| **Gimel Technologies Terms of Service** | Proprietary services including Excluded Components | Apply after license swap when user opts into proprietary services |

The Excluded Components (Type C adapter implementations) are **outside the scope of the MPL 2.0** — the MPL 2.0 does not apply to them. The Gimel Technologies Terms of Service are the sole and independent legal basis for any use of Excluded Components.

**Repository obligations:**

| File | Required | Content |
|------|----------|---------|
| `LICENSE` | Yes | Full MPL 2.0 text + Gimel Foundation Additional Terms appendix |
| `ADDITIONAL-TERMS.md` | Yes | Standalone, reader-friendly description of the three exclusions, the license boundary table, and reference to the Gimel Technologies Terms of Service |

**Key legal points SDK repositories MUST make explicit:**

- The Gimel Foundation Legal Terms apply to all use of GAuth.
- The MPL 2.0 applies to the Open Core components only. It does not extend to the Excluded Components.
- The Excluded Components are not covered by the MPL 2.0. They are outside its scope entirely.
- Use of any proprietary service or Excluded Component (Type C adapter) triggers a license swap from the MPL 2.0 to the Gimel Technologies Terms of Service, as described in §7 (License & ToS State Machine).
- The Gimel Technologies Terms of Service are the sole and independent legal basis governing proprietary features. No rights to create, distribute, or offer competing implementations within the three exclusion domains for the GAuth adapter slot system are granted by the MPL 2.0 or any other part of the Open Core license.
- Contributors to Open Core components license their work under MPL 2.0. Contributions to Excluded Components require a separate Contributor License Agreement (CLA) with the Gimel Foundation.
- For proprietary licensing inquiries: licensing@gimel.foundation

### 15.7 Cross-Language Consistency

All SDK repositories MUST maintain:

- **Identical conformance test vector IDs** — CT-REG-001 through CT-S2S-004 (same IDs, same expected behavior)
- **Identical violation code constants** — Same string values across all languages
- **Identical adapter interface method signatures** — Same method names and parameter shapes (adapted to language idioms)
- **Identical README structure** — Same sections in the same order
- **Identical legal files** — The `LICENSE` and `ADDITIONAL-TERMS.md` files MUST be identical across all repositories

---

## Appendix A: Governance Profile Ceiling Table

Reference table for SDK implementations of CHK-03 and Management API validation.

| Attribute | Minimal | Standard | Strict | Enterprise | Behörde |
|-----------|---------|----------|--------|------------|---------|
| Deployment targets | dev, staging, prod | dev, staging | staging | staging | staging |
| Auto-deploy | Yes | No | No | No | No |
| DB write access | Yes | Yes | Yes | No | No |
| DB migration | Yes | No | No | No | No |
| DB production access | Yes | No | No | No | No |
| Shell mode | any | denylist | allowlist | allowlist | allowlist |
| Packages audited only | No | No | Yes | Yes | Yes |
| Secrets read | Yes | Yes | Yes | No | No |
| Secrets create | Yes | No | No | No | No |
| Agent delegation | Yes | Yes (depth 1) | Yes (depth 1) | No | No |
| Min approval mode | autonomous | supervised | supervised | supervised | four-eyes |
| Max session (min) | ∞ | 240 | 120 | 60 | 30 |
| Max tool calls | ∞ | 500 | 200 | 100 | 100 |
| Max lines/commit | ∞ | 500 | 200 | 100 | 100 |

**Profile-severity interaction:**

| Profile | Adjustment |
|---------|-----------|
| minimal | `must-have` → `nice-to-have` (all violations become warnings) |
| standard | No change |
| strict | No change (Phase 2: multi-signer PoA) |
| enterprise | `nice-to-have` → `must-have` (all violations become blocking) |
| behörde | `nice-to-have` → `must-have` + multi-signer PoA (Vier-Augen-Prinzip) |

---

## Appendix B: Slot Configuration Reference

Extracted from the production `CONNECTOR_SLOT_CONFIGS` for SDK implementers.

| Slot | Number | Adapter Type | Attestation | Null Behavior | Timeout (ms) | Max Retries |
|------|--------|-------------|-------------|---------------|-------------|-------------|
| `pdp` | 1 | Internal | No | Not allowed — mandatory | 5,000 | 0 |
| `oauth_engine` | 2 | A | No | Not allowed — mandatory | 10,000 | 1 |
| `foundry` | 3 | B | No | Features unavailable; no agent execution | 30,000 | 1 |
| `wallet` | 4 | B | No | W3C VC unavailable; JWT-only | 10,000 | 1 |
| `ai_governance` | 5 | C | Yes | AI second-pass skipped; rule-based only | 60,000 | 0 |
| `web3_identity` | 6 | C | Yes | Web3 features unavailable; standard identity | 30,000 | 0 |
| `dna_identity` | 7 | C | Yes | DNA features unavailable; standard identity | 30,000 | 0 |

---

## Appendix C: JSON Schema Registry

All normative schemas are hosted at `gimelfoundation.com`.

| Schema | URI |
|--------|-----|
| PoA Credential | `https://gimelfoundation.com/schemas/poa/v2.2/poa-credential.json` |
| Enforcement Request | `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-request.json` |
| Enforcement Decision | `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-decision.json` |
| Enforcement Error | `https://gimelfoundation.com/schemas/pep/v1.2/enforcement-error.json` |
| Mandate Creation Request | `https://gimelfoundation.com/schemas/mgmt/v1.1/mandate-creation-request.json` |
| Management Error | `https://gimelfoundation.com/schemas/mgmt/v1.1/management-error.json` |
| Sealed Adapter Manifest | `https://gimelfoundation.com/schemas/adapter/v1.0/manifest.json` |

**Well-known endpoints (runtime):**

| Endpoint | URI | Purpose |
|----------|-----|---------|
| Adapter Trusted Keys | `https://gimelfoundation.com/.well-known/adapter-keys.json` | Ed25519 public keys for Type C manifest verification |
| Adapter Revocations | `https://gimelfoundation.com/.well-known/adapter-revocations.json` | Revoked keys and adapter versions for Type C manifests |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-09 | Auth Team | Initial release. All 7 adapter interfaces (+ BillingAdapter Type D), sealed registration protocol with Ed25519 manifest signing (RFC 8032) including JSON schema, JCS canonicalization, trusted namespace rules (`@gimel/*`), and revocation model, A/B/C/D × O/S/M/L tariff gating matrix, two-tier ToS state machine (Platform ToS + Proprietary Service ToS with version-bump re-acceptance), 88 conformance test vectors (18 registration incl. 8 manifest vectors, 31 PEP, 26 management, 9 license/attestation, 4 S2S), RFC cross-reference index, language-specific SDK guidance (Python, TypeScript, Rust, Go, .NET). |
| 1.0.1 | 2026-04-10 | Auth Team | Removed Tariff G from public SDK surface (internal-only). Added Open Core design principle (Tariff O = rule-based PEP enforcement only, no AI governance). Updated tariff gating matrix, algorithm, and conformance test vectors accordingly. |
| 1.1 | 2026-04-10 | Auth Team + SDK Team | License corrected from Apache 2.0 to MPL 2.0 (all open interfaces). Removed internal billing surcharge details from public spec (§3.8, §5.2). Added §13 Open Core Exclusions (three proprietary exclusions explicitly named with license boundary table and Gimel Foundation Additional Terms). Added §14 GitHub Repository Structure (standard repo layout, README requirements, quick-start examples for Python and TypeScript, license/exclusions notice template, cross-language consistency rules). Added §14.6 Legal Framework: layered legal structure distinguishing Gimel Foundation Legal Terms (apply universally) from Gimel Technologies Terms of Service (apply after license swap for proprietary services). Exclusions are outside the scope of MPL 2.0; Gimel Technologies ToS is the sole and independent legal basis. License swap mechanism from MPL 2.0 to Gimel Technologies ToS explicitly documented. Repository legal file obligations and key legal points all SDK repos must make explicit. |
| 1.2 | 2026-04-10 | Auth Team + SDK Team | Added §2 Integration Patterns & Deployment Topology: three deployment patterns (Sidecar — claims provider SDK for existing OAuth servers, Gateway — PEP middleware for API gateways, Full Stack — integrated OAuth+Management+PEP bundle). OAuth Provider Compatibility Matrix with 6 providers (Hydra P0, Keycloak P1, Azure AD/Okta/Auth0 P2, Zitadel P3) mapped to patterns and SDK adapters. Adapter Interface Unification table showing all three patterns converge on the same RFC-defined contracts. All subsequent sections renumbered (+1). PEP schema URIs updated from v1.1 to v1.2 (aligning with RFC 0117 v1.2). "Builds on" updated to reference RFC 0117 v1.2. Appendix C expanded: added PoA Credential schema, Management Error schema, Sealed Adapter Manifest schema, and two well-known endpoints (adapter-keys.json, adapter-revocations.json). RFC Cross-Reference Index updated with integration patterns row. 