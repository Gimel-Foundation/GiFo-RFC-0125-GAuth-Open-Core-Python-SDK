# GAuth Open Core

**Power of Attorney compliance monitoring for AI agents.**

**Version 0.91 — Public Preview**

[![License](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)

GAuth Open Core implements the GAuth protocol suite (GiFo-RFCs 0110, 0111, 0116, 0117, 0118) for governing AI agent behavior through Power of Attorney credentials. It provides mandate lifecycle management, runtime policy enforcement, and compliance monitoring — all rule-based, deterministic, and auditable.

This is a monorepo containing both a **TypeScript reference implementation** (Express 5 Management API + PEP engine) and a **Python SDK**.

---

## Repository Structure

| Directory | Language | Description |
|-----------|----------|-------------|
| `artifacts/api-server/` | TypeScript | Management API (17 endpoints, RFC 0118) and PEP engine (4 endpoints, RFC 0117) on Express 5 |
| `lib/db/` | TypeScript | Drizzle ORM schemas, Zod validation, and shared database types |
| `gauth-core/` | Python | Standalone Python SDK with Pydantic models, PEP engine, management service, and FastAPI HTTP binding |
| `docs/` | — | SDK Implementation Guide (v1.3), Contribution and Release Policy |

## What It Does

GAuth enforces **what an AI agent is allowed to do** at runtime. Every action an agent wants to take is evaluated against a mandate — a structured Power of Attorney credential that specifies:

- **Who** the agent acts for (subject, customer, project)
- **What** the agent may do (verbs, paths, transaction types)
- **How** the agent must behave (governance profile, approval mode, budget)
- **When** the mandate is valid (TTL, session limits, temporal bounds)

The PEP (Policy Enforcement Point) evaluates each action request through a 16-check pipeline and returns a **PERMIT**, **DENY**, or **CONSTRAIN** decision with a full audit trail.

## Governance Profiles

Five predefined profiles control the strictness of agent governance:

| Profile | Approval Mode | Max Session | Delegation |
|---------|--------------|-------------|------------|
| minimal | autonomous | unlimited | yes (unlimited) |
| standard | supervised | 240 min | yes (depth 1) |
| strict | supervised | 120 min | yes (depth 1) |
| enterprise | supervised | 60 min | no |
| behoerde | four-eyes | 30 min | no |

## PEP Evaluation Pipeline

The PEP executes 16 checks in order for every enforcement request:

| # | Check | Description |
|---|-------|-------------|
| CHK-01 | Credential Validation | Verify mandate structure and required fields |
| CHK-02 | Temporal & Status | Check expiry, activation, and mandate status |
| CHK-03 | Governance Profile | Enforce profile ceiling constraints |
| CHK-04 | Phase | Validate operational phase (build, test, deploy, etc.) |
| CHK-05 | Sector | Verify sector restrictions |
| CHK-06 | Region | Check geographic/jurisdictional constraints |
| CHK-07 | Path Authorization | Denied paths override allowed paths |
| CHK-08 | Verb Authorization | Check verb is permitted (hash-verified in stateless mode) |
| CHK-09 | Verb Constraints | Evaluate verb-specific constraints (requires_approval, etc.) |
| CHK-10 | Platform Permissions | Verify platform-level permission grants |
| CHK-11 | Transaction Matrix | Cross-product validation of transaction types |
| CHK-12 | Decision Type | Determine PERMIT vs CONSTRAIN based on accumulated conditions |
| CHK-13 | Budget | Verify and consume budget allocation |
| CHK-14 | Session Limits | Enforce session duration and tool call limits |
| CHK-15 | Approval | Check approval requirements for the action |
| CHK-16 | Delegation Chain | Validate delegation depth and scope narrowing |

## Quick Start

### TypeScript (Management API + PEP)

```bash
pnpm install
pnpm --filter @workspace/api-server run dev
```

The API server starts on port 8080 with:
- Management API: `/api/gauth/mgmt/v1/`
- PEP API: `/api/gauth/pep/v1/`

### Python SDK

```bash
cd gauth-core
pip install -e ".[dev]"
pytest tests/ -v
```

```python
from gauth_core.mgmt import MandateManagementService
from gauth_core.pep import PEPEngine
from gauth_core.storage import InMemoryMandateRepository

repo = InMemoryMandateRepository()
service = MandateManagementService(repo)

mandate = service.create_mandate({
    "parties": {
        "subject": "agent-001",
        "customer_id": "cust-123",
        "project_id": "proj-456",
        "issued_by": "admin@example.com",
    },
    "scope": {
        "governance_profile": "standard",
        "phase": "build",
        "core_verbs": {
            "file.read": {"allowed": True},
            "file.write": {"allowed": True, "requires_approval": True},
        },
        "allowed_paths": ["src/", "tests/"],
        "denied_paths": [".env", "secrets/"],
    },
    "requirements": {
        "approval_mode": "supervised",
        "budget": {"total_cents": 10000},
        "ttl_seconds": 43200,
    },
})

activated = service.activate_mandate(mandate["mandate_id"], "admin@example.com")
engine = PEPEngine(repository=repo)

decision = engine.enforce_action(
    credential={
        "mandate_id": activated["mandate_id"],
        "subject": "agent-001",
        "governance_profile": "standard",
        "phase": "build",
        "core_verbs": {"file.read": {"allowed": True}},
        "allowed_paths": ["src/"],
        "denied_paths": [".env"],
        "approval_mode": "supervised",
        "budget_total_cents": 10000,
        "budget_remaining_cents": 10000,
        "scope_checksum": "sha256:...",
        "status": "ACTIVE",
    },
    action={"verb": "file.read", "resource": "src/main.py"},
    context={"agent_id": "agent-001", "timestamp": "2026-04-09T12:00:00Z"},
)

print(decision["decision"])  # PERMIT, DENY, or CONSTRAIN
```

## RFC Coverage

| RFC | Title | Implementation |
|-----|-------|---------------|
| GiFo-RFC 0110 | Protocol Engine | Architecture model, P*P pattern |
| GiFo-RFC 0111 | Authorization Framework | Roles, flows, delegation |
| GiFo-RFC 0116 | Interoperability Layer | Schema types (Zod + Pydantic), wire format |
| GiFo-RFC 0117 | PEP Interface | 16-check pipeline, stateless/stateful modes, two-pass delegation |
| GiFo-RFC 0118 | Management API | 17 endpoints: mandate lifecycle, budget, delegation, audit |

## Documentation

- [SDK Implementation Guide Version 0.91](docs/gauth-sdk-implementation-guide.md) — canonical reference for SDK teams
- [Contribution and Release Policy v1.0](docs/contribution-and-release-policy.md) — branch model, CI gates, release workflow
- [Contributing](gauth-core/CONTRIBUTING.md) — how to contribute (community PRs and architecture team workflow)

## License — Dual-Layer Coexistence

This project is licensed under the [Mozilla Public License 2.0](LICENSE).

| Layer | License | Scope | Revocable? |
|-------|---------|-------|------------|
| SDK source code | MPL 2.0 | File-level copyleft on SDK files; your own files in separate modules remain under your chosen license | No — irrevocable, as long as acting in line with MPL 2.0 as well as the Legal Terms of Gimel Foundation |
| Proprietary Gimel services | Gimel Technologies ToS | Governs access to Gimel-hosted services (Auth-as-a-Service, Foundry, Wallet, managed infrastructure, Type C adapters) | Yes — service relationship |
| Open specifications (RFCs) | Apache 2.0 | Interoperability protocols (RFC 0116, 0117, 0118) | No — irrevocable |

You may run the SDK in pure Open Core mode (MPL 2.0 only, self-hosted, no Gimel services) indefinitely. If you choose to use proprietary Gimel services, the Gimel Technologies ToS applies in addition to MPL 2.0 — not as a replacement. Your SDK code and modifications remain MPL 2.0 regardless.

**Downgrade protection:** Your MPL 2.0 license rights are irrevocable as long as you are acting in line with MPL 2.0 as well as the Legal Terms of Gimel Foundation. Violation of the Gimel Foundation Additional Terms may result in termination of access to proprietary services, but does not retroactively affect MPL 2.0 rights to previously-released SDK source code.

**Three functional domains are excluded from the MPL 2.0 scope** and require separate proprietary licensing from the Gimel Foundation:

1. **AI-Enabled Governance** — AI/ML-based policy generation, risk scoring, or compliance assessment beyond the deterministic PEP engine
2. **Web3 Integration** — Blockchain, DLT, decentralized identity, or token-gated access control
3. **DNA-Based Identities / Post-Quantum Cryptography** — Biometric identity from genomic data, PQC algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, SPHINCS+, etc.)

See [ADDITIONAL-TERMS.md](ADDITIONAL-TERMS.md) for the full legal text.

For proprietary licensing inquiries: info@gimelid.com

Copyright (c) 2024-2026 Gimel Foundation gGmbH i.G.
