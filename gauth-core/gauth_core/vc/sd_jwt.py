"""SD-JWT selective disclosure — Gap Spec G-07 Step 4."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _create_disclosure(claim_name: str, claim_value: Any) -> tuple[str, str]:
    salt = secrets.token_urlsafe(16)
    disclosure_array = [salt, claim_name, claim_value]
    disclosure_json = json.dumps(disclosure_array, separators=(",", ":"))
    encoded = _base64url_encode(disclosure_json.encode())
    digest = _base64url_encode(hashlib.sha256(encoded.encode()).digest())
    return encoded, digest


def create_sd_jwt(
    vc_payload: dict[str, Any],
    disclosed_claims: list[str] | None = None,
    redacted_claims: list[str] | None = None,
) -> dict[str, Any]:
    if not redacted_claims:
        redacted_claims = []
    if not disclosed_claims:
        disclosed_claims = list(vc_payload.keys())

    disclosures: list[str] = []
    sd_digests: list[str] = []

    credential_subject = vc_payload.get("credentialSubject", vc_payload.get("vc", {}).get("credentialSubject", {}))

    for key, value in credential_subject.items():
        if key in redacted_claims:
            encoded, digest = _create_disclosure(key, value)
            disclosures.append(encoded)
            sd_digests.append(digest)

    issuer_payload = dict(vc_payload)
    if credential_subject and redacted_claims:
        redacted_subject = {
            k: v for k, v in credential_subject.items()
            if k not in redacted_claims
        }
        if "credentialSubject" in issuer_payload:
            issuer_payload["credentialSubject"] = redacted_subject
        elif "vc" in issuer_payload and "credentialSubject" in issuer_payload["vc"]:
            issuer_payload["vc"] = dict(issuer_payload["vc"])
            issuer_payload["vc"]["credentialSubject"] = redacted_subject

    if sd_digests:
        issuer_payload["_sd"] = sd_digests
        issuer_payload["_sd_alg"] = "sha-256"

    header = _base64url_encode(json.dumps({"alg": "ES256", "typ": "vc+sd-jwt"}).encode())
    payload = _base64url_encode(json.dumps(issuer_payload, default=str).encode())
    sig_placeholder = _base64url_encode(b"stub-signature")
    compact_jwt = f"{header}.{payload}.{sig_placeholder}"

    sd_jwt_compact = compact_jwt
    for d in disclosures:
        sd_jwt_compact += f"~{d}"
    sd_jwt_compact += "~"

    return {
        "compact": sd_jwt_compact,
        "disclosures": disclosures,
        "sd_digests": sd_digests,
        "holder_binding": None,
    }


def verify_sd_jwt_disclosures(
    sd_jwt_compact: str,
) -> dict[str, Any]:
    parts = sd_jwt_compact.split("~")
    jwt_part = parts[0] if parts else ""
    disclosures = [p for p in parts[1:] if p]

    if not jwt_part:
        return {"valid": False, "reason": "Empty JWT part", "revealed_claims": {},
                "disclosure_count": 0, "verified_disclosures": []}

    jwt_parts = jwt_part.split(".")
    payload_claims: dict[str, Any] = {}
    if len(jwt_parts) >= 2:
        try:
            payload_json = _base64url_decode(jwt_parts[1]).decode()
            payload_claims = json.loads(payload_json)
        except Exception:
            return {"valid": False, "reason": "Failed to decode JWT payload",
                    "revealed_claims": {}, "disclosure_count": 0, "verified_disclosures": []}

    sd_digests = payload_claims.get("_sd", [])

    revealed_claims: dict[str, Any] = {}
    verified_disclosures: list[dict[str, Any]] = []
    all_digests_valid = True

    for disclosure in disclosures:
        digest = _base64url_encode(hashlib.sha256(disclosure.encode()).digest())
        in_sd = digest in sd_digests

        if not in_sd and sd_digests:
            all_digests_valid = False

        try:
            decoded = _base64url_decode(disclosure).decode()
            arr = json.loads(decoded)
            if isinstance(arr, list) and len(arr) == 3:
                _, claim_name, claim_value = arr
                revealed_claims[claim_name] = claim_value
                verified_disclosures.append({
                    "disclosure": disclosure,
                    "digest": digest,
                    "in_sd": in_sd,
                    "claim_name": claim_name,
                })
            else:
                all_digests_valid = False
                verified_disclosures.append({
                    "disclosure": disclosure,
                    "digest": digest,
                    "in_sd": in_sd,
                    "error": "Disclosure is not a 3-element array",
                })
        except Exception as exc:
            all_digests_valid = False
            verified_disclosures.append({
                "disclosure": disclosure,
                "digest": digest,
                "in_sd": in_sd,
                "error": str(exc),
            })

    valid = all_digests_valid
    if sd_digests and not disclosures:
        valid = False

    return {
        "valid": valid,
        "revealed_claims": revealed_claims,
        "disclosure_count": len(disclosures),
        "verified_disclosures": verified_disclosures,
        "sd_alg": payload_claims.get("_sd_alg", "sha-256"),
    }
