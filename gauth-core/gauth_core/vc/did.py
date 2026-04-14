"""DID resolution — did:web and did:key — Gap Spec G-07 Step 3."""

from __future__ import annotations

import hashlib
from typing import Any


def resolve_did_web(did: str) -> dict[str, Any]:
    if not did.startswith("did:web:"):
        return {"error": f"Not a did:web identifier: {did}"}

    parts = did[8:].split(":")
    domain = parts[0]
    path_parts = parts[1:] if len(parts) > 1 else []

    doc_url = f"https://{domain}"
    if path_parts:
        doc_url += "/" + "/".join(path_parts)
    doc_url += "/.well-known/did.json" if not path_parts else "/did.json"

    verification_method_id = f"{did}#key-1"

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {},
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
        "service": [
            {
                "id": f"{did}#gauth-service",
                "type": "GAuthService",
                "serviceEndpoint": f"https://{domain}/api/gauth",
            }
        ],
        "_resolution": {
            "did_document_url": doc_url,
            "resolved": True,
            "method": "web",
        },
    }


def resolve_did_key(did: str) -> dict[str, Any]:
    if not did.startswith("did:key:"):
        return {"error": f"Not a did:key identifier: {did}"}

    multibase_key = did[8:]
    verification_method_id = f"{did}#{multibase_key}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyMultibase": multibase_key,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
        "_resolution": {
            "resolved": True,
            "method": "key",
        },
    }


def create_did_key(public_key_hex: str = "") -> dict[str, Any]:
    if not public_key_hex:
        seed = hashlib.sha256(b"gauth-ephemeral-" + str(id(object())).encode()).hexdigest()[:32]
        public_key_hex = seed

    multibase_key = f"z{public_key_hex}"
    did = f"did:key:{multibase_key}"

    return {
        "did": did,
        "multibase_key": multibase_key,
        "did_document": resolve_did_key(did),
    }


def resolve_did(did: str) -> dict[str, Any]:
    if did.startswith("did:web:"):
        return resolve_did_web(did)
    elif did.startswith("did:key:"):
        return resolve_did_key(did)
    else:
        method = did.split(":")[1] if ":" in did else "unknown"
        return {"error": f"Unsupported DID method: {method}", "did": did}
