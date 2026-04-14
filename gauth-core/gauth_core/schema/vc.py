"""W3C Verifiable Credentials schema types — RFC 0116 §7 / Gap Spec G-07.

Types for VC Data Model v2.0, DID resolution, Data Integrity Proofs,
SD-JWT selective disclosure, Bitstring Status List, and OpenID4VCI/VP.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


GAUTH_VC_CONTEXT = "https://gauth.gimel.foundation/credentials/v1"
W3C_CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"


class DataIntegrityProof(BaseModel):
    type: str = "DataIntegrityProof"
    cryptosuite: str = "ecdsa-rdfc-2019"
    created: datetime | None = None
    verification_method: str = Field(default="", alias="verificationMethod")
    proof_purpose: str = Field(default="assertionMethod", alias="proofPurpose")
    proof_value: str = Field(default="", alias="proofValue")

    model_config = ConfigDict(populate_by_name=True)


class BitstringStatusListEntry(BaseModel):
    id: str = ""
    type: str = "BitstringStatusListEntry"
    status_purpose: str = Field(default="revocation", alias="statusPurpose")
    status_list_index: int = Field(default=0, alias="statusListIndex")
    status_list_credential: str = Field(default="", alias="statusListCredential")

    model_config = ConfigDict(populate_by_name=True)


class CredentialSubject(BaseModel):
    id: str = ""
    mandate_id: str = ""
    governance_profile: str = ""
    phase: str = ""
    approval_mode: str = ""
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_sectors: list[str] = Field(default_factory=list)
    allowed_regions: list[str] = Field(default_factory=list)
    allowed_decisions: list[str] = Field(default_factory=list)
    budget_total_cents: int = 0
    budget_remaining_cents: int = 0
    scope_checksum: str = ""
    tool_permissions_hash: str = ""
    platform_permissions_hash: str = ""


class VerifiableCredential(BaseModel):
    context: list[str] = Field(
        default_factory=lambda: [W3C_CREDENTIALS_V2_CONTEXT, GAUTH_VC_CONTEXT],
        alias="@context",
    )
    id: str = ""
    type: list[str] = Field(
        default_factory=lambda: ["VerifiableCredential", "GAuthPoACredential"],
    )
    issuer: dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime | None = Field(default=None, alias="validFrom")
    valid_until: datetime | None = Field(default=None, alias="validUntil")
    credential_subject: CredentialSubject = Field(
        default_factory=CredentialSubject,
        alias="credentialSubject",
    )
    credential_status: BitstringStatusListEntry | None = Field(
        default=None,
        alias="credentialStatus",
    )
    credential_schema: dict[str, Any] | None = Field(
        default=None,
        alias="credentialSchema",
    )
    proof: DataIntegrityProof | None = None

    model_config = ConfigDict(populate_by_name=True)


class VerifiablePresentation(BaseModel):
    context: list[str] = Field(
        default_factory=lambda: [W3C_CREDENTIALS_V2_CONTEXT],
        alias="@context",
    )
    id: str = ""
    type: list[str] = Field(
        default_factory=lambda: ["VerifiablePresentation"],
    )
    holder: str = ""
    verifiable_credential: list[dict[str, Any]] = Field(
        default_factory=list,
        alias="verifiableCredential",
    )
    proof: DataIntegrityProof | None = None

    model_config = ConfigDict(populate_by_name=True)


class StorageReceipt(BaseModel):
    credential_id: str
    stored_at: datetime
    storage_type: str = "local"
    integrity_hash: str = ""


class PresentationQuery(BaseModel):
    credential_types: list[str] = Field(default_factory=list)
    holder_did: str | None = None
    challenge: str | None = None
    domain: str | None = None


class CredentialFilter(BaseModel):
    type: str | None = None
    issuer: str | None = None
    subject: str | None = None
    status: str | None = None


class CredentialSummary(BaseModel):
    credential_id: str
    type: list[str] = Field(default_factory=list)
    issuer: str = ""
    subject: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    status: str = ""


class DeletionReceipt(BaseModel):
    credential_id: str
    deleted_at: datetime
    reason: str = ""


class SDFrame(BaseModel):
    disclosed_claims: list[str] = Field(default_factory=list)
    redacted_claims: list[str] = Field(default_factory=list)


class SDJWT(BaseModel):
    compact: str = ""
    disclosures: list[str] = Field(default_factory=list)
    holder_binding: str | None = None


class DIDDocument(BaseModel):
    context: list[str] = Field(
        default_factory=lambda: ["https://www.w3.org/ns/did/v1"],
        alias="@context",
    )
    id: str = ""
    verification_method: list[dict[str, Any]] = Field(
        default_factory=list,
        alias="verificationMethod",
    )
    authentication: list[str] = Field(default_factory=list)
    assertion_method: list[str] = Field(
        default_factory=list,
        alias="assertionMethod",
    )
    service: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class OpenID4VCICredentialOffer(BaseModel):
    credential_issuer: str = ""
    credential_configuration_ids: list[str] = Field(default_factory=list)
    grants: dict[str, Any] = Field(default_factory=dict)


class OpenID4VPPresentationDefinition(BaseModel):
    id: str = ""
    input_descriptors: list[dict[str, Any]] = Field(default_factory=list)
    format: dict[str, Any] = Field(default_factory=dict)
