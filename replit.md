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

## GAuth Open Core (Python SDK)

- **Location**: `gauth-core/`
- **Python**: 3.10+
- **Core dependency**: Pydantic v2
- **Optional**: FastAPI (install with `pip install gauth-core[http]`)
- **License**: Apache 2.0
- **Test command**: `cd gauth-core && python -m pytest tests/ -v`
- **Tests**: 104 tests across 6 test modules

### Submodules (9 total)

| Module | Purpose |
|--------|---------|
| `schema/` | Pydantic v2 models, enums, error codes (RFC 0116) |
| `profiles/` | 5 governance profiles, ceiling table (14 attributes each) |
| `utils/` | SHA-256 canonical JSON checksums |
| `validation/` | 3-stage pipeline (schema, ceiling, consistency C-1..C-4) |
| `storage/` | Abstract repository + InMemory implementation |
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
