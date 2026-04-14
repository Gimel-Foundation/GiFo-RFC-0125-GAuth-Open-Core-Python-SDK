# Workspace

## Overview

pnpm workspace monorepo using TypeScript. Each package manages its own dependencies.

Additionally contains the **GAuth Open Core Python SDK** (`gauth-core/`) — a Power of Attorney compliance monitoring library for AI agents.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **TypeScript version**: 5.9
- **API framework**: Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (from OpenAPI spec)
- **Build**: esbuild (CJS bundle)

## GAuth TypeScript Schema & Types (lib/db)

- **Location**: `lib/db/src/schema/`
- **Database**: PostgreSQL + Drizzle ORM tables (mandates, audit_logs, delegations, budget_consumption)
- **Zod schemas**: All RFC 0116/0118 request/response types, PoA credential, validation result
- **Ceilings**: 5 governance profiles with 14+ ceiling attributes each
- **Validation**: 3-stage pipeline (schema parse, ceiling enforcement, consistency C-1..C-6)
- **Checksums**: SHA-256 via RFC 8785 JCS-compatible canonical JSON
- **Errors**: 22 management error codes with HTTP status mappings
- **Schema push**: `pnpm --filter @workspace/db run push`

### Schema Files

| File | Purpose |
|------|---------|
| `enums.ts` | pgEnum definitions, TS literal types, constants (TERMINAL_STATUSES, APPROVAL_MODE_RANK), Tariff codes (O, S, M, L, M+O, L+O), DEPLOYMENT_POLICY_MATRIX with S column, SLOT_TYPE_CLASSIFICATION (A/B/C), TYPE_C_SLOTS, checkTariffGate(), PoaMapSummary types |
| `mandates.ts` | Drizzle pgTable definitions (mandates, audit_logs, delegations, budget_consumption) |
| `zod-schemas.ts` | Zod v4 schemas for all API request/response types, PoA credential |
| `ceilings.ts` | CeilingDefinition interface + CEILING_TABLE constant + validateAgainstCeiling() |
| `checksums.ts` | canonicalJson(), computeScopeChecksum(), computeToolPermissionsHash(), computePlatformPermissionsHash() |
| `validation.ts` | validateSchema(), validateCeilings(), validateConsistency(), validateMandate() |
| `errors.ts` | ManagementErrorCode type, ERROR_CODE_HTTP_STATUS map, ManagementError class |

## GAuth Management API (Express 5)

- **Location**: `artifacts/api-server/src/routes/gauth-mgmt.ts` (routes), `artifacts/api-server/src/lib/mgmt-service.ts` (service layer)
- **Base path**: `/api/gauth/mgmt/v1/`
- **17 endpoints**: mandate CRUD, status transitions, budget ops, TTL extension, delegation, profiles, health
- **Authentication**: HMAC-SHA256 Bearer token auth (`GAUTH_API_SECRET` env var), plus `X-Caller-Identity` header for caller attribution
- **Activation atomicity**: partial unique index `mandates_active_subject_project_idx` enforces at most one ACTIVE mandate per (subject, project_id) at the DB level
- **Transactional safety**: activation (supersession), budget consumption, and delegation use explicit PostgreSQL transactions with `SELECT ... FOR UPDATE` row locking for concurrency safety
- **Idempotent consumption**: duplicate `(mandate_id, enforcement_request_id)` composite key returns current budget state (no double deduction)
- **Cascade**: revocation/suspension propagates synchronously to all child delegations
- **Delegation coherence**: child mandate `requirements` reflect actual delegated budget/TTL (not inherited parent values)
- **TTL ceiling validation**: extensions validated against governance profile `maxSessionDurationMinutes`
- **Error handling**: ManagementError → structured JSON responses with correct HTTP status codes

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /mandates | Create DRAFT mandate |
| GET | /mandates | List with filter/pagination |
| GET | /mandates/:id | Get mandate detail |
| DELETE | /mandates/:id | Delete DRAFT only |
| GET | /mandates/:id/history | Audit trail |
| POST | /mandates/:id/activate | DRAFT→ACTIVE (with supersession) |
| POST | /mandates/:id/revoke | ACTIVE\|SUSPENDED→REVOKED (cascade) |
| POST | /mandates/:id/suspend | ACTIVE→SUSPENDED (cascade) |
| POST | /mandates/:id/resume | SUSPENDED→ACTIVE (expiry check) |
| POST | /mandates/:id/budget/increase | Additive-only budget increase |
| POST | /mandates/:id/budget/consume | Idempotent PEP consumption |
| GET | /mandates/:id/budget | Current budget state |
| POST | /mandates/:id/ttl/extend | Additive-only TTL extension |
| POST | /delegations | Create child delegation |
| GET | /mandates/:id/delegation-chain | Full ancestry chain |
| GET | /profiles | List governance profiles |
| GET | /profiles/:profile/ceilings | Profile ceiling table |
| GET | /health | Version and feature flags |

## GAuth PEP Engine (TypeScript)

- **Location**: `artifacts/api-server/src/lib/pep-service.ts` (engine), `artifacts/api-server/src/routes/gauth-pep.ts` (routes)
- **Base path**: `/api/gauth/pep/v1/`
- **Types**: `lib/db/src/schema/pep-types.ts` — EnforcementRequest/Decision schemas, 29 violation codes (V-001..V-099)
- **Authentication**: Same HMAC-SHA256 Bearer token as mgmt API (enforce/batch-enforce only; health/policy are open)
- **Enforcement modes**: stateless (credential snapshot), stateful (live mandate lookup)
- **Fail-closed**: stateful mode returns DENY if live mandate lookup fails; budget consumption failure downgrades PERMIT to DENY
- **Agent binding**: CHK-02 verifies `context.agent_id == credential.subject`
- **Two-pass delegation**: Pass 1 runs CHK-01–CHK-15, Pass 2 re-evaluates CHK-05–CHK-12 against effective (narrowed) scope with `-P2` suffix
- **CHK-16**: Validates chain continuity, monotonic `max_depth_remaining`, `delegated_at` temporal validity, and last delegate == presenting agent

### PEP Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /enforce | Yes | Single enforcement request |
| POST | /batch-enforce | Yes | Batch enforcement (parallel) |
| GET | /policy | No | Supported checks, modes, profiles |
| GET | /health | No | PEP status and version |

### 16 Checks

CHK-01 Credential Structure, CHK-02 Temporal & Agent Binding, CHK-03 Governance Profile Ceiling, CHK-04 Phase Match, CHK-05 Sector Allowlist, CHK-06 Region Allowlist, CHK-07 Path Evaluation, CHK-08 Verb Authorization, CHK-09 Verb Constraints, CHK-10 Platform Permissions, CHK-11 Transaction Matrix, CHK-12 Decision Type Allowlist, CHK-13 Budget Check, CHK-14 Session Limits, CHK-15 Approval Verification, CHK-16 Delegation Chain Validation, CHK-ESC Auth PEP Escalation (hybrid cascade)

### Hybrid Cascade Escalation

When a local rule-based evaluation yields CONSTRAIN and an `AuthPEPClient` is configured, the PEP forwards the request to Auth PEP for a definitive decision. If Auth PEP is unreachable, the system preserves the local CONSTRAIN result as a rule-based-only fallback (CHK-ESC severity=warning). Both Python (`PEPEngine(auth_pep_client=...)`) and TypeScript (`setAuthPEPClient(...)`) support this pattern.

## GAuth Open Core (Python SDK)

- **Location**: `gauth-core/`
- **Python**: 3.10+
- **Core dependency**: Pydantic v2
- **Optional**: FastAPI (install with `pip install gauth-core[http]`)
- **License**: MPL 2.0 (see Python SDK note below)
- **Test command**: `cd gauth-core && python -m pytest tests/ -v`
- **Tests**: 304 tests across 9 test modules

### Submodules (10 total)

| Module | Purpose |
|--------|---------|
| `schema/` | Pydantic v2 models, enums, error codes, W3C VC types (RFC 0116) |
| `profiles/` | 5 governance profiles, ceiling table (15 attributes each incl. approval_required_for_delegation) |
| `utils/` | SHA-256 canonical JSON checksums |
| `validation/` | 3-stage pipeline (schema, ceiling, consistency C-1..C-6) |
| `storage/` | Abstract repository + InMemory + SQLAlchemy implementations |
| `adapters/` | Protected adapter system (9 slots, tariff gate, Type C Ed25519 manifest verification, trust validation) |
| `mgmt/` | Mandate lifecycle service (RFC 0118) with delegation approval gate + PoA map summary |
| `pep/` | 16-check enforcement engine, two-pass delegation, OAuth pre-check, full CHK-09 constraint eval (RFC 0117) |
| `vc/` | W3C VC translation layer: PoA→VC serialization, DID resolution, Data Integrity Proofs, SD-JWT, Bitstring Status List, OpenID4VCI/VP stubs |
| `http/` | Optional FastAPI binding (17 mgmt + 4 PEP endpoints) |

### Key Concepts

- **Governance profiles**: minimal, standard, strict, enterprise, behoerde
- **PEP decisions**: PERMIT, DENY, CONSTRAIN
- **Enforcement modes**: stateless (JWT-only), stateful (live mandate lookup)
- **Tariff model**: 6 tariff codes (O, S, M, L, M+O, L+O); S/M/L standalone, M+O/L+O hybrid; tariff gate enforced at register()
- **Adapter trust**: namespace verification (`gauth_adapters_gimel.*`), HMAC signature, or `allow_untrusted=True` (GAUTH_DEV_MODE=true only)
- **Type C slots**: ai_governance, web3_identity, dna_identity — require Ed25519 signed manifest (fail-closed)
- **Budget**: additive-only increases; consumption tracked with idempotency keys
- **Delegation**: scope narrowing, budget carving, depth limits per profile, approval gate (supervised=1, four-eyes=2 approvers)
- **W3C VC**: PoA→VC Data Model v2.0 serialization, DID resolution (did:web, did:key), Data Integrity Proofs, SD-JWT, Bitstring Status List, OpenID4VCI/VP stubs
- **Mandatory slots**: oauth_engine (unregister rejected)

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally
- `cd gauth-core && python -m pytest tests/ -v` — run GAuth SDK test suite

## License

- **License**: Mozilla Public License 2.0 (MPL 2.0) with Gimel Foundation Additional Terms
- **License file**: `LICENSE`
- **Open Core scope**: Python SDK, TypeScript Management API, database schemas, PEP engine, governance profiles
- **Excluded Components** (proprietary licensing required):
  1. AI-Enabled Governance — ML/AI-augmented policy, risk scoring, anomaly detection
  2. Web3 Integration — blockchain, DLT, DID, token-gated access
  3. DNA-Based Identities & PQC — biometric identity via genomic data, post-quantum cryptographic schemes
- **Contributor note**: contributions to Open Core components are MPL 2.0; Excluded Components require a separate CLA with Gimel Foundation

## SDK Implementation Guide

- **Location**: `docs/gauth-sdk-implementation-guide.md`
- **Version**: 0.91 (Public Preview)
- **Contents**: Full SDK reference covering adapter type system (A/B/C/D), 7-slot connector model, sealed registration protocol (Ed25519 manifest), tariff gating matrix (O/M+O/L+O), ToS coexistence model, PEP integration (hybrid cascade with rule-based-only fallback), Management API client, S2S authentication, 88+ conformance test vectors, Open Core Exclusions (§13), GitHub Repository Structure (§14), and deployment pattern cross-reference (§2.7)
- **License**: MPL 2.0 (open interfaces); Gimel ToS (Type C proprietary interfaces)

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
