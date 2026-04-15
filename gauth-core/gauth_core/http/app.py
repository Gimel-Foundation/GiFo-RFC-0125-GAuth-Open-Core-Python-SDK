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
from gauth_core.vc.openid import OpenID4VCIssuer, OpenID4VPVerifier
from gauth_core.vc.status_list import BitstringStatusList


def create_app(
    repository: MandateRepository | None = None,
    adapter_registry: AdapterRegistry | None = None,
    signing_key: Any | None = None,
    status_list: BitstringStatusList | None = None,
) -> Any:
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the HTTP binding. "
            "Install with: pip install gauth-core[http]"
        )

    repo = repository or InMemoryMandateRepository()
    mgmt_service = MandateManagementService(repo)
    pep_engine = PEPEngine(repository=repo, adapter_registry=adapter_registry)
    vci_issuer = OpenID4VCIssuer(signing_key=signing_key)
    vp_verifier = OpenID4VPVerifier(status_list=status_list)

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

    @app.get("/.well-known/openid-credential-issuer")
    async def vci_issuer_metadata() -> JSONResponse:
        return JSONResponse(content=vci_issuer.get_issuer_metadata())

    @app.post("/gauth/vci/v1/offers")
    async def vci_create_offer(request: Request) -> JSONResponse:
        body = await request.json()
        mandate_id = body.get("mandate_id", "")
        mandate = None
        if mandate_id:
            try:
                mandate = mgmt_service.get_mandate(mandate_id)
            except ManagementError:
                raise HTTPException(status_code=404, detail="Mandate not found")
        result = vci_issuer.create_credential_offer(
            mandate=mandate or body.get("mandate", {}),
            credential_type=body.get("credential_type", "GAuthPoACredential"),
        )
        return JSONResponse(status_code=201, content=result)

    @app.post("/gauth/vci/v1/token")
    async def vci_token(request: Request) -> JSONResponse:
        body = await request.json()
        result = vci_issuer.token_endpoint(body.get("pre-authorized_code", ""))
        if "error" in result:
            return JSONResponse(status_code=400, content=result)
        return JSONResponse(content=result)

    @app.post("/gauth/vci/v1/credentials")
    async def vci_credential(request: Request) -> JSONResponse:
        body = await request.json()
        auth_header = request.headers.get("authorization", "")
        access_token = ""
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
        elif body.get("access_token"):
            access_token = body["access_token"]
        result = vci_issuer.credential_endpoint(
            access_token=access_token,
            c_nonce=body.get("c_nonce", ""),
            credential_type=body.get("credential_type", "GAuthPoACredential"),
            proof=body.get("proof"),
        )
        if "error" in result:
            return JSONResponse(status_code=400, content=result)
        return JSONResponse(content=result)

    @app.post("/gauth/vp/v1/presentation-requests")
    async def vp_create_request(request: Request) -> JSONResponse:
        body = await request.json()
        result = vp_verifier.create_presentation_request(
            credential_types=body.get("credential_types"),
            purpose=body.get("purpose", "GAuth PoA verification"),
        )
        return JSONResponse(status_code=201, content=result)

    @app.post("/gauth/vp/v1/presentation-requests/{session_id}/response")
    async def vp_submit_presentation(session_id: str, request: Request) -> JSONResponse:
        body = await request.json()
        result = vp_verifier.submit_presentation(
            session_id=session_id,
            vp_token=body.get("vp_token", ""),
            presentation_submission=body.get("presentation_submission"),
        )
        status_code = 200 if result.get("verified") else 400
        return JSONResponse(status_code=status_code, content=result)

    @app.get("/gauth/vp/v1/presentation-requests/{session_id}")
    async def vp_session_status(session_id: str) -> JSONResponse:
        result = vp_verifier.get_session_status(session_id)
        if "error" in result:
            return JSONResponse(status_code=404, content=result)
        return JSONResponse(content=result)

    return app
