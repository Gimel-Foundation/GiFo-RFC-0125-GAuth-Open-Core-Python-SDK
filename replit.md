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
| `enums.ts` | pgEnum definitions, TS literal types, constants (TERMINAL_STATUSES, APPROVAL_MODE_RANK) |
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

## GAuth Open Core (Python SDK)

- **Location**: `gauth-core/`
- **Python**: 3.10+
- **Core dependency**: Pydantic v2
- **Optional**: FastAPI (install with `pip install gauth-core[http]`)
- **License**: Apache 2.0
- **Test command**: `cd gauth-core && python -m pytest tests/ -v`
- **Tests**: 130 tests across 6 test modules

### Submodules (9 total)

| Module | Purpose |
|--------|---------|
| `schema/` | Pydantic v2 models, enums, error codes (RFC 0116) |
| `profiles/` | 5 governance profiles, ceiling table (14 attributes each) |
| `utils/` | SHA-256 canonical JSON checksums |
| `validation/` | 3-stage pipeline (schema, ceiling, consistency C-1..C-6) |
| `storage/` | Abstract repository + InMemory + SQLAlchemy implementations |
| `adapters/` | Protected adapter system (4 slots, trust validation) |
| `mgmt/` | Mandate lifecycle service (RFC 0118) |
| `pep/` | 16-check enforcement engine, two-pass delegation (RFC 0117) |
| `http/` | Optional FastAPI binding (17 mgmt + 4 PEP endpoints) |

### Key Concepts

- **Governance profiles**: minimal, standard, strict, enterprise, behoerde
- **PEP decisions**: PERMIT, DENY, CONSTRAIN
- **Enforcement modes**: stateless (JWT-only), stateful (live mandate lookup)
- **Adapter trust**: namespace verification (`gauth_adapters_gimel.*`), HMAC signature, or `allow_untrusted=True` for dev
- **Budget**: additive-only increases; consumption tracked with idempotency keys
- **Delegation**: scope narrowing, budget carving, depth limits per profile

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run dev` — run API server locally
- `cd gauth-core && python -m pytest tests/ -v` — run GAuth SDK test suite

See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details.
