"""OpenID4VCI/VP stub implementations — Gap Spec G-07 Step 6."""

from __future__ import annotations

import uuid
from typing import Any


class OpenID4VCIStub:

    def __init__(self, issuer_url: str = "https://gauth.gimel.foundation") -> None:
        self._issuer_url = issuer_url
        self._offered: dict[str, dict[str, Any]] = {}

    def create_credential_offer(
        self,
        credential_type: str = "GAuthPoACredential",
        grant_type: str = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ) -> dict[str, Any]:
        offer_id = f"offer_{uuid.uuid4().hex[:12]}"
        offer = {
            "credential_issuer": self._issuer_url,
            "credential_configuration_ids": [credential_type],
            "grants": {
                grant_type: {
                    "pre-authorized_code": f"code_{uuid.uuid4().hex[:16]}",
                    "tx_code": {
                        "input_mode": "numeric",
                        "length": 6,
                    },
                },
            },
        }
        self._offered[offer_id] = offer
        return {"offer_id": offer_id, **offer}

    def get_issuer_metadata(self) -> dict[str, Any]:
        return {
            "credential_issuer": self._issuer_url,
            "credential_endpoint": f"{self._issuer_url}/credentials",
            "credential_configurations_supported": {
                "GAuthPoACredential": {
                    "format": "jwt_vc_json",
                    "scope": "gauth_poa",
                    "cryptographic_binding_methods_supported": ["did:key", "did:web"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "credential_definition": {
                        "type": ["VerifiableCredential", "GAuthPoACredential"],
                    },
                },
            },
            "display": [
                {
                    "name": "GAuth Open Core",
                    "locale": "en-US",
                },
            ],
        }

    def token_endpoint(self, pre_authorized_code: str) -> dict[str, Any]:
        return {
            "access_token": f"tok_{uuid.uuid4().hex[:16]}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "c_nonce": f"nonce_{uuid.uuid4().hex[:8]}",
            "c_nonce_expires_in": 300,
        }

    def credential_endpoint(
        self,
        access_token: str,
        credential_type: str = "GAuthPoACredential",
        proof: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "format": "jwt_vc_json",
            "credential": f"stub.vc.jwt.{uuid.uuid4().hex[:8]}",
            "c_nonce": f"nonce_{uuid.uuid4().hex[:8]}",
            "c_nonce_expires_in": 300,
        }


class OpenID4VPStub:

    def __init__(self, verifier_url: str = "https://gauth.gimel.foundation/verify") -> None:
        self._verifier_url = verifier_url
        self._sessions: dict[str, dict[str, Any]] = {}

    def create_presentation_request(
        self,
        credential_types: list[str] | None = None,
        purpose: str = "GAuth PoA verification",
    ) -> dict[str, Any]:
        if credential_types is None:
            credential_types = ["GAuthPoACredential"]

        session_id = f"vp_{uuid.uuid4().hex[:12]}"
        nonce = f"nonce_{uuid.uuid4().hex[:12]}"

        request = {
            "session_id": session_id,
            "presentation_definition": {
                "id": f"pd_{uuid.uuid4().hex[:8]}",
                "input_descriptors": [
                    {
                        "id": f"id_{i}",
                        "name": ctype,
                        "purpose": purpose,
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$.type"],
                                    "filter": {
                                        "type": "array",
                                        "contains": {"const": ctype},
                                    },
                                },
                            ],
                        },
                    }
                    for i, ctype in enumerate(credential_types)
                ],
                "format": {
                    "jwt_vc_json": {"alg": ["ES256"]},
                    "jwt_vp_json": {"alg": ["ES256"]},
                },
            },
            "nonce": nonce,
            "response_uri": f"{self._verifier_url}/response/{session_id}",
            "response_mode": "direct_post",
        }

        self._sessions[session_id] = {
            "status": "pending",
            "nonce": nonce,
            "credential_types": credential_types,
        }

        return request

    def submit_presentation(
        self,
        session_id: str,
        vp_token: str,
        presentation_submission: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {"verified": False, "error": "Session not found"}

        session["status"] = "verified"
        session["vp_token"] = vp_token

        return {
            "verified": True,
            "session_id": session_id,
            "credential_types_verified": session.get("credential_types", []),
        }

    def get_session_status(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        return {
            "session_id": session_id,
            "status": session.get("status", "unknown"),
        }
