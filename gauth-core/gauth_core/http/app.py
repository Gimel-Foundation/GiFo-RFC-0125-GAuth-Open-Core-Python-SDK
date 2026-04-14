"""FastAPI application factory — creates mountable ASGI app with all GAuth routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from gauth_core.adapters.registry import AdapterRegistry
from gauth_core.mgmt.service import MandateManagementService, ManagementError
from gauth_core.pep.engine import PEPEngine
from gauth_core.schema.enums import ERROR_CODE_HTTP_STATUS, ManagementErrorCode
from gauth_core.storage.base import MandateRepository
from gauth_core.storage.memory import InMemoryMandateRepository


def create_app(
    repository: MandateRepository | None = None,
    adapter_registry: AdapterRegistry | None = None,
) -> Any:
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the HTTP binding. "
            "Install with: pip install gauth-core[http]"
        )

    repo = repository or InMemoryMandateRepository()
    mgmt_service = MandateManagementService(repo)
    pep_engine = PEPEngine(repository=repo, adapter_registry=adapter_registry)

    app = FastAPI(
        title="GAuth Open Core",
        description="GAuth Protocol Suite — Management API & PEP (RFCs 0116, 0117, 0118)",
        version="0.91.0",
    )

    @app.exception_handler(ManagementError)
    async def management_error_handler(request: Request, exc: ManagementError) -> JSONResponse:
        status_code = ERROR_CODE_HTTP_STATUS.get(exc.code, 500)
        return JSONResponse(
            status_code=status_code,
            content={
                "error_code": exc.code.value,
                "message": exc.message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": exc.details,
            },
        )

    @app.post("/gauth/mgmt/v1/mandates")
    async def create_mandate(request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.create_mandate(body)
        return JSONResponse(status_code=201, content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/activate")
    async def activate_mandate(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.activate_mandate(mandate_id, body.get("activated_by", ""))
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/revoke")
    async def revoke_mandate(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.revoke_mandate(mandate_id, body.get("revoked_by", ""), body.get("reason", ""))
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/suspend")
    async def suspend_mandate(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.suspend_mandate(mandate_id, body.get("suspended_by", ""), body.get("reason", ""))
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/resume")
    async def resume_mandate(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.resume_mandate(mandate_id, body.get("resumed_by", ""), body.get("reason", ""))
        return JSONResponse(content=result)

    @app.delete("/gauth/mgmt/v1/mandates/{mandate_id}")
    async def delete_mandate(mandate_id: str) -> JSONResponse:
        result = mgmt_service.delete_draft(mandate_id)
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/mandates/{mandate_id}")
    async def get_mandate(mandate_id: str) -> JSONResponse:
        result = mgmt_service.get_mandate(mandate_id)
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/mandates")
    async def list_mandates(
        status: str | None = None,
        agent_id: str | None = None,
        project_id: str | None = None,
        governance_profile: str | None = None,
        cursor: str | None = None,
        limit: int = 20,
    ) -> JSONResponse:
        result = mgmt_service.list_mandates(
            status=status, agent_id=agent_id, project_id=project_id,
            governance_profile=governance_profile, cursor=cursor, limit=limit,
        )
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/mandates/{mandate_id}/history")
    async def get_history(mandate_id: str) -> JSONResponse:
        result = mgmt_service.get_history(mandate_id)
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/budget/increase")
    async def increase_budget(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.increase_budget(
            mandate_id, body.get("additional_cents", 0), body.get("increased_by", ""),
        )
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/budget/consume")
    async def consume_budget(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.consume_budget(
            mandate_id,
            body.get("enforcement_request_id", ""),
            body.get("consumed_cents", 0),
            body.get("action_verb", ""),
            body.get("resource", ""),
        )
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/mandates/{mandate_id}/budget")
    async def get_budget(mandate_id: str) -> JSONResponse:
        result = mgmt_service.get_budget_state(mandate_id)
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/mandates/{mandate_id}/ttl/extend")
    async def extend_ttl(mandate_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.extend_ttl(
            mandate_id, body.get("additional_seconds", 0), body.get("extended_by", ""),
        )
        return JSONResponse(content=result)

    @app.post("/gauth/mgmt/v1/delegations")
    async def create_delegation(request: Request) -> JSONResponse:
        body = await request.json()
        result = mgmt_service.create_delegation(
            body.get("parent_mandate_id", ""),
            body.get("delegate_agent_id", ""),
            body.get("scope_restriction", {}),
            body.get("budget_cents", 0),
            body.get("ttl_seconds", 60),
            body.get("delegated_by", ""),
        )
        return JSONResponse(status_code=201, content=result)

    @app.get("/gauth/mgmt/v1/mandates/{mandate_id}/delegation-chain")
    async def get_delegation_chain(mandate_id: str) -> JSONResponse:
        result = mgmt_service.get_delegation_chain(mandate_id)
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/mandates/{mandate_id}/poa-map")
    async def get_poa_map(mandate_id: str) -> JSONResponse:
        result = mgmt_service.generate_poa_map(mandate_id)
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/profiles")
    async def list_profiles() -> JSONResponse:
        result = mgmt_service.get_profiles()
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/profiles/{profile_name}/ceilings")
    async def get_ceilings(profile_name: str) -> JSONResponse:
        result = mgmt_service.get_profile_ceilings(profile_name)
        return JSONResponse(content=result)

    @app.get("/gauth/mgmt/v1/health")
    async def mgmt_health() -> JSONResponse:
        return JSONResponse(content={
            "status": "ok",
            "mgmt_version": "1.1.0",
            "interface_version": "1.1",
            "supported_schema_version": "0116.2.2",
            "features": {
                "suspension": True,
                "ttl_extension": True,
                "budget_consumption_reporting": True,
            },
        })

    @app.post("/gauth/pep/v1/enforce")
    async def pep_enforce(request: Request) -> JSONResponse:
        body = await request.json()
        result = pep_engine.enforce_action(request=body)
        response = JSONResponse(content=result)
        response.headers["X-PEP-Interface-Version"] = "1.1"
        return response

    @app.post("/gauth/pep/v1/batch-enforce")
    async def pep_batch_enforce(request: Request) -> JSONResponse:
        body = await request.json()
        results = pep_engine.batch_enforce(body.get("requests", []))
        response = JSONResponse(content={"results": results})
        response.headers["X-PEP-Interface-Version"] = "1.1"
        return response

    @app.get("/gauth/pep/v1/policy")
    async def pep_policy() -> JSONResponse:
        result = pep_engine.get_enforcement_policy()
        response = JSONResponse(content=result)
        response.headers["X-PEP-Interface-Version"] = "1.1"
        return response

    @app.get("/gauth/pep/v1/health")
    async def pep_health() -> JSONResponse:
        result = pep_engine.health()
        response = JSONResponse(content=result)
        response.headers["X-PEP-Interface-Version"] = "1.1"
        return response

    return app
