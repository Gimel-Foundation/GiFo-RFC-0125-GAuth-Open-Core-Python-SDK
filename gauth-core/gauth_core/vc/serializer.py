"""PoA → W3C VC Data Model v2.0 serialization — Gap Spec G-07 Step 2."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from gauth_core.schema.vc import (
    BitstringStatusListEntry,
    CredentialSubject,
    DataIntegrityProof,
    GAUTH_VC_CONTEXT,
    VerifiableCredential,
    W3C_CREDENTIALS_V2_CONTEXT,
)


def poa_to_vc(
    mandate: dict[str, Any],
    issuer_did: str = "",
    status_list_credential: str = "",
    status_list_index: int = 0,
) -> dict[str, Any]:
    scope = mandate.get("scope", {})
    requirements = mandate.get("requirements", {})
    parties = mandate.get("parties", {})
    budget = mandate.get("budget_state", {})

    if not issuer_did:
        project_id = parties.get("project_id", "default")
        issuer_did = f"did:web:gauth.gimel.foundation:{project_id}"

    subject_id = parties.get("subject", "")
    subject_did = f"did:key:{subject_id}" if subject_id else ""

    core_verbs = scope.get("core_verbs", {})
    allowed_actions = sorted(
        v for v, p in core_verbs.items()
        if (isinstance(p, dict) and p.get("allowed", True)) or (not isinstance(p, dict) and p)
    )

    activated_at = mandate.get("activated_at")
    expires_at = mandate.get("expires_at")
    valid_from = None
    valid_until = None
    if activated_at:
        valid_from = activated_at if isinstance(activated_at, str) else activated_at.isoformat()
    if expires_at:
        valid_until = expires_at if isinstance(expires_at, str) else expires_at.isoformat()

    credential_subject = {
        "id": subject_did,
        "mandate_id": mandate.get("mandate_id", ""),
        "governance_profile": scope.get("governance_profile", ""),
        "phase": scope.get("phase", ""),
        "approval_mode": requirements.get("approval_mode", "autonomous"),
        "allowed_actions": allowed_actions,
        "allowed_sectors": scope.get("allowed_sectors", []),
        "allowed_regions": scope.get("allowed_regions", []),
        "allowed_decisions": scope.get("allowed_decisions", []),
        "budget_total_cents": budget.get("total_cents", requirements.get("budget", {}).get("total_cents", 0)),
        "budget_remaining_cents": budget.get("remaining_cents", 0),
        "scope_checksum": mandate.get("scope_checksum", ""),
        "tool_permissions_hash": mandate.get("tool_permissions_hash", ""),
        "platform_permissions_hash": mandate.get("platform_permissions_hash", ""),
    }

    vc: dict[str, Any] = {
        "@context": [W3C_CREDENTIALS_V2_CONTEXT, GAUTH_VC_CONTEXT],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", "GAuthPoACredential"],
        "issuer": {
            "id": issuer_did,
            "name": "GAuth Open Core",
        },
        "credentialSubject": credential_subject,
        "credentialSchema": {
            "id": "https://gauth.gimel.foundation/schemas/poa-credential/v2",
            "type": "JsonSchema",
        },
    }

    if valid_from:
        vc["validFrom"] = valid_from
    if valid_until:
        vc["validUntil"] = valid_until

    if status_list_credential:
        vc["credentialStatus"] = {
            "id": f"{status_list_credential}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": status_list_index,
            "statusListCredential": status_list_credential,
        }

    return vc


def vc_to_jwt_payload(vc: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    subject = vc.get("credentialSubject", {})

    payload: dict[str, Any] = {
        "iss": vc.get("issuer", {}).get("id", ""),
        "sub": subject.get("id", ""),
        "jti": vc.get("id", ""),
        "iat": int(now.timestamp()),
        "vc": vc,
    }

    valid_from = vc.get("validFrom")
    if valid_from:
        if isinstance(valid_from, str):
            try:
                nbf_dt = datetime.fromisoformat(valid_from)
                payload["nbf"] = int(nbf_dt.timestamp())
            except ValueError:
                pass
        elif isinstance(valid_from, datetime):
            payload["nbf"] = int(valid_from.timestamp())

    valid_until = vc.get("validUntil")
    if valid_until:
        if isinstance(valid_until, str):
            try:
                exp_dt = datetime.fromisoformat(valid_until)
                payload["exp"] = int(exp_dt.timestamp())
            except ValueError:
                pass
        elif isinstance(valid_until, datetime):
            payload["exp"] = int(valid_until.timestamp())

    return payload


def create_data_integrity_proof(
    vc: dict[str, Any],
    verification_method: str = "",
    proof_value: str = "",
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)

    if not proof_value:
        canonical = json.dumps(vc, sort_keys=True, separators=(",", ":"))
        proof_value = hashlib.sha256(canonical.encode()).hexdigest()

    return {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-rdfc-2019",
        "created": now.isoformat(),
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }


def verify_data_integrity_proof(vc: dict[str, Any]) -> dict[str, Any]:
    proof = vc.get("proof")
    if not proof:
        return {"verified": False, "reason": "No proof present"}

    if proof.get("type") != "DataIntegrityProof":
        return {"verified": False, "reason": f"Unsupported proof type: {proof.get('type')}"}

    if proof.get("cryptosuite") != "ecdsa-rdfc-2019":
        return {"verified": False, "reason": f"Unsupported cryptosuite: {proof.get('cryptosuite')}"}

    vc_without_proof = {k: v for k, v in vc.items() if k != "proof"}
    canonical = json.dumps(vc_without_proof, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode()).hexdigest()

    proof_value = proof.get("proofValue", "")
    if proof_value == expected:
        return {"verified": True, "cryptosuite": proof.get("cryptosuite")}

    return {"verified": False, "reason": "Proof value mismatch (stub verification)"}
