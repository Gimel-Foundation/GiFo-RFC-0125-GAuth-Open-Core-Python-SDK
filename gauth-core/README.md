# GAuth Open Core — Python SDK

**Power of Attorney compliance monitoring for AI agents.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()

GAuth Open Core is a Python SDK implementing the complete GAuth protocol suite (GiFo-RFCs 0110, 0111, 0116, 0117, 0118). It provides PoA credential management, runtime enforcement, and lifecycle operations for governing AI agent behavior.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  GAuth Open Core SDK                                     │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Schema   │  │ Management   │  │ PEP Engine        │  │
│  │ Layer    │  │ Service      │  │ (16-check pipeline)│  │
│  │ (Pydantic│  │ (RFC 0118)   │  │ (RFC 0117)        │  │
│  │  models) │  │              │  │                   │  │
│  └──────────┘  └──────────────┘  └───────────────────┘  │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Profiles │  │ Validation   │  │ Adapter System    │  │
│  │ (5 gov.  │  │ Pipeline     │  │ (Protected ext.   │  │
│  │ profiles)│  │ (3-stage)    │  │  points)          │  │
│  └──────────┘  └──────────────┘  └───────────────────┘  │
│                                                         │
│  ┌──────────┐  ┌──────────────────────────────────────┐  │
│  │ Storage  │  │ HTTP Binding (FastAPI, optional)     │  │
│  │ (Abstract│  │ 17 Mgmt + 4 PEP endpoints           │  │
│  │ + Memory)│  │                                      │  │
│  └──────────┘  └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Installation

```bash
pip install gauth-core
```

With optional HTTP binding (FastAPI):

```bash
pip install gauth-core[http]
```

## Quick Start

### Create and activate a mandate

```python
from gauth_core.mgmt import MandateManagementService
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
print(f"Mandate {activated['mandate_id']} active until {activated['expires_at']}")
```

### Enforce an action

```python
from gauth_core.pep import PEPEngine

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

print(f"Decision: {decision['decision']}")  # PERMIT, DENY, or CONSTRAIN
print(f"Checks evaluated: {decision['audit']['checks_evaluated']}")
```

### Run as HTTP server

```python
from gauth_core.http import create_app

app = create_app()
# Mount in any ASGI application, or run directly:
# uvicorn main:app --host 0.0.0.0 --port 8000
```

## Governance Profiles

| Profile | Approval | Session | Tool Calls | Delegation |
|---------|----------|---------|------------|------------|
| minimal | autonomous | unlimited | unlimited | yes (unlimited) |
| standard | supervised | 240 min | 500 | yes (depth 1) |
| strict | supervised | 120 min | 200 | yes (depth 1) |
| enterprise | supervised | 60 min | 100 | no |
| behoerde | four-eyes | 30 min | 100 | no |

## PEP Evaluation Pipeline

The PEP executes 16 checks in order for every enforcement request:

| Check | Name | Stateless | Stateful |
|-------|------|-----------|----------|
| CHK-01 | Credential Validation | Full | Full |
| CHK-02 | Temporal & Status | Partial | Full |
| CHK-03 | Governance Profile | Stateless attrs | Full |
| CHK-04 | Phase | Full | Full |
| CHK-05 | Sector | Full | Full |
| CHK-06 | Region | Full | Full |
| CHK-07 | Path (denied > allowed) | Full | Full |
| CHK-08 | Verb Authorization | Hash-only | Full |
| CHK-09 | Verb Constraints | No | Full |
| CHK-10 | Platform Permissions | Hash-only | Full |
| CHK-11 | Transaction | Full | Full |
| CHK-12 | Decision Type | Full | Full |
| CHK-13 | Budget | Stale | Live |
| CHK-14 | Session Limits | If provided | Full |
| CHK-15 | Approval | No | Full |
| CHK-16 | Delegation Chain | Partial | Full |

## Adapter System

The SDK includes a protected adapter system for plugging in proprietary services:

```python
from gauth_core.adapters import AdapterRegistry

registry = AdapterRegistry(
    trusted_namespaces=frozenset({"gauth_adapters_gimel"}),
)
# Only adapters from trusted namespaces can be registered
# Default no-op adapters are used for all slots
```

**Adapter slots:**
- `AIEnrichmentAdapter` — Pre-evaluation AI enrichment
- `RiskScoringAdapter` — Composite risk assessment
- `RegulatoryReasoningAdapter` — Regulatory interpretation
- `ComplianceEnrichmentAdapter` — Post-evaluation compliance

## RFC Coverage

| RFC | Title | Coverage |
|-----|-------|----------|
| 0110 | Protocol Engine | Architecture model |
| 0111 | Authorization Framework | Roles and flows |
| 0116 | Interoperability Layer | Schema types (Pydantic) |
| 0117 | PEP Interface | 16-check pipeline, two-pass delegation |
| 0118 | Management API | 17 endpoints, lifecycle, budget, delegation |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with HTTP binding
pip install -e ".[http]"
python -c "from gauth_core.http import create_app; app = create_app()"
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Gimel Foundation.
