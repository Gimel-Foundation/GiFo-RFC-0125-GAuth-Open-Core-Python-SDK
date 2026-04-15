"""OpenID4VCI/VP credential exchange — RFC 0116 §7 interoperability."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import uuid
from typing import Any

from gauth_core.vc.serializer import (
    create_data_integrity_proof,
    poa_to_vc,
    verify_data_integrity_proof,
)
from gauth_core.vc.status_list import BitstringStatusList


class _NonceStore:

    def __init__(self, default_ttl: int = 300) -> None:
        self._nonces: dict[str, float] = {}
        self._used: set[str] = set()
        self._default_ttl = default_ttl

    def issue(self, ttl: int | None = None) -> tuple[str, int]:
        nonce = f"c_nonce_{secrets.token_urlsafe(24)}"
        effective_ttl = ttl or self._default_ttl
        self._nonces[nonce] = time.time() + effective_ttl
        return nonce, effective_ttl

    def validate_and_consume(self, nonce: str) -> dict[str, Any]:
        if nonce in self._used:
            return {"valid": False, "reason": "nonce_replay"}
        expiry = self._nonces.get(nonce)
        if expiry is None:
            return {"valid": False, "reason": "nonce_unknown"}
        if time.time() > expiry:
            self._nonces.pop(nonce, None)
            return {"valid": False, "reason": "nonce_expired"}
        self._nonces.pop(nonce, None)
        self._used.add(nonce)
        return {"valid": True}

    def cleanup_expired(self) -> int:
        now = time.time()
        expired = [n for n, exp in self._nonces.items() if now > exp]
        for n in expired:
            self._nonces.pop(n, None)
        return len(expired)


class TrustedIssuerRegistry:

    def __init__(self) -> None:
        self._keys: dict[str, Any] = {}

    def register(self, issuer_did: str, public_key: Any) -> None:
        self._keys[issuer_did] = public_key

    def resolve(self, verification_method: str) -> Any | None:
        did = verification_method.split("#")[0] if "#" in verification_method else verification_method
        return self._keys.get(did)


class OpenID4VCIssuer:

    def __init__(
        self,
        issuer_url: str = "https://gauth.gimel.foundation",
        signing_key: Any | None = None,
        verification_method: str = "",
        nonce_ttl: int = 300,
    ) -> None:
        self._issuer_url = issuer_url
        if signing_key is None:
            from cryptography.hazmat.primitives.asymmetric import ec
            self._signing_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self._signing_key = signing_key
        self._verification_method = verification_method
        self._nonces = _NonceStore(default_ttl=nonce_ttl)
        self._codes: dict[str, dict[str, Any]] = {}
        self._tokens: dict[str, dict[str, Any]] = {}
        self._offers: dict[str, dict[str, Any]] = {}

    @property
    def verification_key(self) -> Any:
        return self._signing_key.public_key()

    @property
    def issuer_did(self) -> str:
        return f"did:web:{self._issuer_url.replace('https://', '').replace('http://', '')}"

    def create_credential_offer(
        self,
        mandate: dict[str, Any] | None = None,
        credential_type: str = "GAuthPoACredential",
        grant_type: str = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    ) -> dict[str, Any]:
        offer_id = f"offer_{uuid.uuid4().hex[:12]}"
        pre_auth_code = f"code_{secrets.token_urlsafe(24)}"

        self._codes[pre_auth_code] = {
            "mandate": mandate or {},
            "credential_type": credential_type,
            "created_at": time.time(),
            "consumed": False,
        }

        offer = {
            "credential_issuer": self._issuer_url,
            "credential_configuration_ids": [credential_type],
            "grants": {
                grant_type: {
                    "pre-authorized_code": pre_auth_code,
                },
            },
        }
        self._offers[offer_id] = offer
        return {"offer_id": offer_id, **offer}

    def get_issuer_metadata(self) -> dict[str, Any]:
        return {
            "credential_issuer": self._issuer_url,
            "credential_endpoint": f"{self._issuer_url}/gauth/vci/v1/credentials",
            "token_endpoint": f"{self._issuer_url}/gauth/vci/v1/token",
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
            "display": [{"name": "GAuth Open Core", "locale": "en-US"}],
        }

    def token_endpoint(self, pre_authorized_code: str) -> dict[str, Any]:
        code_entry = self._codes.get(pre_authorized_code)
        if not code_entry:
            return {"error": "invalid_grant", "error_description": "Unknown pre-authorized code"}
        if code_entry["consumed"]:
            return {"error": "invalid_grant", "error_description": "Code already consumed"}

        code_entry["consumed"] = True

        access_token = f"tok_{secrets.token_urlsafe(24)}"
        c_nonce, c_nonce_ttl = self._nonces.issue()

        self._tokens[access_token] = {
            "mandate": code_entry["mandate"],
            "credential_type": code_entry["credential_type"],
            "created_at": time.time(),
            "expires_at": time.time() + 3600,
        }

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "c_nonce": c_nonce,
            "c_nonce_expires_in": c_nonce_ttl,
        }

    def credential_endpoint(
        self,
        access_token: str,
        c_nonce: str = "",
        credential_type: str = "GAuthPoACredential",
        proof: dict[str, Any] | None = None,
        issuer_did: str = "",
        status_list_credential: str = "",
        status_list_index: int = 0,
    ) -> dict[str, Any]:
        token_entry = self._tokens.get(access_token)
        if not token_entry:
            return {"error": "invalid_token", "error_description": "Unknown or expired access token"}
        if time.time() > token_entry["expires_at"]:
            self._tokens.pop(access_token, None)
            return {"error": "invalid_token", "error_description": "Access token expired"}

        if not c_nonce:
            return {
                "error": "invalid_proof",
                "error_description": "c_nonce is required for credential issuance",
                "c_nonce_error": "nonce_missing",
            }
        nonce_result = self._nonces.validate_and_consume(c_nonce)
        if not nonce_result["valid"]:
            return {
                "error": "invalid_proof",
                "error_description": f"Nonce validation failed: {nonce_result['reason']}",
                "c_nonce_error": nonce_result["reason"],
            }

        mandate = token_entry["mandate"]
        effective_issuer = issuer_did or self.issuer_did

        vc = poa_to_vc(
            mandate,
            issuer_did=effective_issuer,
            status_list_credential=status_list_credential,
            status_list_index=status_list_index,
        )

        proof_obj = create_data_integrity_proof(
            vc,
            verification_method=self._verification_method or f"{effective_issuer}#key-1",
            signing_key=self._signing_key,
        )
        vc["proof"] = proof_obj

        new_nonce, new_nonce_ttl = self._nonces.issue()

        return {
            "format": "jwt_vc_json",
            "credential": vc,
            "c_nonce": new_nonce,
            "c_nonce_expires_in": new_nonce_ttl,
        }


def create_verifiable_presentation(
    vc: dict[str, Any],
    challenge: str,
    holder_did: str = "",
    signing_key: Any | None = None,
) -> dict[str, Any]:
    vp: dict[str, Any] = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [vc],
    }
    if holder_did:
        vp["holder"] = holder_did

    vp_without_proof = dict(vp)
    proof_obj = create_data_integrity_proof(
        vp_without_proof,
        verification_method=f"{holder_did}#key-1" if holder_did else "",
        signing_key=signing_key,
        challenge=challenge,
    )
    vp["proof"] = proof_obj
    return vp


class OpenID4VPVerifier:

    def __init__(
        self,
        verifier_url: str = "https://gauth.gimel.foundation/verify",
        status_list: BitstringStatusList | None = None,
        session_ttl: int = 600,
        trusted_issuers: TrustedIssuerRegistry | None = None,
    ) -> None:
        self._verifier_url = verifier_url
        self._status_list = status_list
        self._nonces = _NonceStore(default_ttl=session_ttl)
        self._sessions: dict[str, dict[str, Any]] = {}
        self._session_ttl = session_ttl
        self._trusted_issuers = trusted_issuers or TrustedIssuerRegistry()

    def register_trusted_issuer(self, issuer_did: str, public_key: Any) -> None:
        self._trusted_issuers.register(issuer_did, public_key)

    def create_presentation_request(
        self,
        credential_types: list[str] | None = None,
        purpose: str = "GAuth PoA verification",
    ) -> dict[str, Any]:
        if credential_types is None:
            credential_types = ["GAuthPoACredential"]

        session_id = f"vp_{uuid.uuid4().hex[:12]}"
        nonce, nonce_ttl = self._nonces.issue(ttl=self._session_ttl)

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
            "nonce_expires_in": nonce_ttl,
            "response_uri": f"{self._verifier_url}/gauth/vp/v1/presentation-requests/{session_id}/response",
            "response_mode": "direct_post",
        }

        self._sessions[session_id] = {
            "status": "pending",
            "nonce": nonce,
            "credential_types": credential_types,
            "created_at": time.time(),
            "expires_at": time.time() + self._session_ttl,
        }

        return request

    def submit_presentation(
        self,
        session_id: str,
        vp_token: dict[str, Any] | str,
        presentation_submission: dict[str, Any] | None = None,
        verification_key: Any | None = None,
    ) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {"verified": False, "error": "session_not_found"}

        if time.time() > session["expires_at"]:
            session["status"] = "expired"
            return {"verified": False, "error": "session_expired"}

        nonce = session["nonce"]
        nonce_result = self._nonces.validate_and_consume(nonce)
        if not nonce_result["valid"]:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": f"nonce_{nonce_result['reason']}",
                "nonce_error": nonce_result["reason"],
            }

        if isinstance(vp_token, str):
            session["status"] = "rejected"
            return {"verified": False, "error": "vp_token_must_be_vc_object"}

        vp_types = vp_token.get("type", [])
        is_vp_wrapper = "VerifiablePresentation" in vp_types

        if is_vp_wrapper:
            return self._verify_vp_wrapper(session_id, session, vp_token, nonce, verification_key)
        else:
            return self._verify_bare_vc(session_id, session, vp_token, verification_key)

    def _verify_vp_wrapper(
        self,
        session_id: str,
        session: dict[str, Any],
        vp: dict[str, Any],
        nonce: str,
        verification_key: Any | None,
    ) -> dict[str, Any]:
        vp_proof = vp.get("proof", {})
        if not isinstance(vp_proof, dict):
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "proof_verification_failed",
                "proof_error": "VP must include a proof",
            }

        if vp_proof.get("challenge") != nonce:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "proof_verification_failed",
                "proof_error": "VP proof challenge must match session nonce",
            }

        vp_verify_result = verify_data_integrity_proof(vp, verification_key=verification_key)
        if not vp_verify_result["verified"]:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "proof_verification_failed",
                "proof_error": f"VP proof invalid: {vp_verify_result.get('reason', '')}",
            }

        vcs = vp.get("verifiableCredential", [])
        if not vcs:
            session["status"] = "rejected"
            return {"verified": False, "error": "no_credentials_in_presentation"}

        all_matched_types: list[str] = []
        for vc in vcs:
            if not isinstance(vc, dict):
                session["status"] = "rejected"
                return {"verified": False, "error": "invalid_credential_in_presentation"}

            vc_key: Any | None = None
            vc_proof = vc.get("proof", {})
            vm = vc_proof.get("verificationMethod", "") if isinstance(vc_proof, dict) else ""
            resolved = self._trusted_issuers.resolve(vm)
            if resolved is not None:
                vc_key = resolved
            if vc_key is None:
                vc_key = verification_key

            vc_verify = verify_data_integrity_proof(vc, verification_key=vc_key)
            if not vc_verify["verified"]:
                session["status"] = "rejected"
                return {
                    "verified": False,
                    "error": "proof_verification_failed",
                    "proof_error": f"VC proof invalid: {vc_verify.get('reason', '')}",
                }

            if self._status_list and "credentialStatus" in vc:
                revocation = self._status_list.check_revocation(vc["credentialStatus"])
                if revocation["revoked"]:
                    session["status"] = "rejected"
                    return {
                        "verified": False,
                        "error": "credential_revoked",
                        "revocation_reason": revocation.get("reason", ""),
                    }

            vc_types = vc.get("type", [])
            expected = session.get("credential_types", [])
            for t in expected:
                if t in vc_types and t not in all_matched_types:
                    all_matched_types.append(t)

        expected_types = session.get("credential_types", [])
        if not all_matched_types:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "credential_type_mismatch",
                "expected_types": expected_types,
                "received_types": [t for vc in vcs if isinstance(vc, dict) for t in vc.get("type", [])],
            }

        session["status"] = "verified"
        session["vp_token"] = vp

        return {
            "verified": True,
            "session_id": session_id,
            "credential_types_verified": all_matched_types,
            "proof_mode": vp_verify_result.get("mode", ""),
            "cryptosuite": vp_verify_result.get("cryptosuite", ""),
        }

    def _verify_bare_vc(
        self,
        session_id: str,
        session: dict[str, Any],
        vc: dict[str, Any],
        verification_key: Any | None,
    ) -> dict[str, Any]:
        effective_key = verification_key
        if effective_key is None:
            vc_proof = vc.get("proof", {})
            vm = vc_proof.get("verificationMethod", "") if isinstance(vc_proof, dict) else ""
            resolved = self._trusted_issuers.resolve(vm)
            if resolved is not None:
                effective_key = resolved

        verification_result = verify_data_integrity_proof(vc, verification_key=effective_key)
        if not verification_result["verified"]:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "proof_verification_failed",
                "proof_error": verification_result.get("reason", ""),
            }

        if self._status_list and "credentialStatus" in vc:
            status_entry = vc["credentialStatus"]
            revocation = self._status_list.check_revocation(status_entry)
            if revocation["revoked"]:
                session["status"] = "rejected"
                return {
                    "verified": False,
                    "error": "credential_revoked",
                    "revocation_reason": revocation.get("reason", ""),
                }

        vc_types = vc.get("type", [])
        expected_types = session.get("credential_types", [])
        matched_types = [t for t in expected_types if t in vc_types]

        if not matched_types:
            session["status"] = "rejected"
            return {
                "verified": False,
                "error": "credential_type_mismatch",
                "expected_types": expected_types,
                "received_types": vc_types,
            }

        session["status"] = "verified"
        session["vp_token"] = vc

        return {
            "verified": True,
            "session_id": session_id,
            "credential_types_verified": matched_types,
            "proof_mode": verification_result.get("mode", ""),
            "cryptosuite": verification_result.get("cryptosuite", ""),
        }

    def get_session_status(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        return {
            "session_id": session_id,
            "status": session.get("status", "unknown"),
        }


OpenID4VCIStub = OpenID4VCIssuer
OpenID4VPStub = OpenID4VPVerifier
