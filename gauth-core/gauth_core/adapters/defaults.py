"""No-op/pass-through default adapter implementations.

These are the default adapters shipped with the open-source SDK.
They perform no AI enrichment, risk scoring, regulatory reasoning,
compliance analysis, OAuth, governance, Web3 identity, DNA identity,
or wallet operations — they simply pass through with empty results.
"""

from __future__ import annotations

from typing import Any

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    ComplianceEnrichmentAdapter,
    DnaIdentityAdapter,
    GovernanceAdapter,
    OAuthEngineAdapter,
    RegulatoryReasoningAdapter,
    RiskScoringAdapter,
    WalletAdapter,
    Web3IdentityAdapter,
)


class NoOpAIEnrichmentAdapter(AIEnrichmentAdapter):

    ADAPTER_TYPE = "ai_enrichment"

    def enrich(
        self,
        enforcement_request: dict[str, Any],
        mandate: dict[str, Any],
    ) -> dict[str, Any]:
        return {"enrichment_source": "noop", "signals": []}

    def health_check(self) -> bool:
        return True


class NoOpRiskScoringAdapter(RiskScoringAdapter):

    ADAPTER_TYPE = "risk_scoring"

    def score(
        self,
        mandate_data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"score": 0.0, "factors": [], "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpRegulatoryReasoningAdapter(RegulatoryReasoningAdapter):

    ADAPTER_TYPE = "regulatory_reasoning"

    def analyze(
        self,
        mandate_data: dict[str, Any],
        regulatory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"requirements": [], "recommendations": [], "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpComplianceEnrichmentAdapter(ComplianceEnrichmentAdapter):

    ADAPTER_TYPE = "compliance_enrichment"

    def evaluate(
        self,
        enforcement_decision: dict[str, Any],
        enforcement_request: dict[str, Any],
    ) -> dict[str, Any]:
        return {"compliance_results": [], "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpOAuthEngineAdapter(OAuthEngineAdapter):

    ADAPTER_TYPE = "oauth_engine"

    def issue_token(
        self,
        grant_type: str,
        client_id: str,
        scope: list[str] | None = None,
        claims: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"access_token": "", "token_type": "bearer", "source": "noop"}

    def validate_token(self, token: str) -> dict[str, Any]:
        return {"active": True, "source": "noop"}

    def revoke_token(self, token: str, token_type_hint: str = "access_token") -> dict[str, Any]:
        return {"revoked": False, "source": "noop"}

    def get_jwks(self) -> dict[str, Any]:
        return {"keys": [], "source": "noop"}

    def introspect(self, token: str) -> dict[str, Any]:
        return {"active": True, "source": "noop"}

    def before_token_issuance(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"proceed": True, "source": "noop"}

    def after_token_issuance(self, token_response: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        return {"processed": True, "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpGovernanceAdapter(GovernanceAdapter):

    ADAPTER_TYPE = "governance"

    def evaluate_governance_policy(
        self,
        mandate: dict[str, Any],
        action: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {"compliant": True, "source": "noop"}

    def get_governance_requirements(
        self,
        profile: str,
        sector: str | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        return {"requirements": [], "source": "noop"}

    def validate_compliance_state(
        self,
        mandate_id: str,
        current_state: dict[str, Any],
    ) -> dict[str, Any]:
        return {"valid": True, "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpWeb3IdentityAdapter(Web3IdentityAdapter):

    ADAPTER_TYPE = "web3_identity"

    def resolve_did(self, did: str) -> dict[str, Any]:
        return {"did": did, "resolved": False, "source": "noop"}

    def verify_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return {"verified": False, "source": "noop"}

    def create_presentation(
        self,
        credentials: list[dict[str, Any]],
        holder_did: str,
        challenge: str | None = None,
    ) -> dict[str, Any]:
        return {"presentation": {}, "source": "noop"}

    def verify_presentation(self, presentation: dict[str, Any]) -> dict[str, Any]:
        return {"verified": False, "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpDnaIdentityAdapter(DnaIdentityAdapter):

    ADAPTER_TYPE = "dna_identity"

    def verify_identity(
        self,
        subject: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        return {"verified": False, "source": "noop"}

    def get_identity_assurance_level(
        self,
        subject: str,
    ) -> dict[str, Any]:
        return {"assurance_level": "none", "source": "noop"}

    def create_identity_binding(
        self,
        subject: str,
        mandate_id: str,
        binding_type: str = "standard",
    ) -> dict[str, Any]:
        return {"binding_id": "", "source": "noop"}

    def health_check(self) -> bool:
        return True


class NoOpWalletAdapter(WalletAdapter):

    ADAPTER_TYPE = "wallet"

    def store_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return {"stored": False, "source": "noop"}

    def retrieve_credential(self, credential_id: str) -> dict[str, Any] | None:
        return None

    def list_credentials(self, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return []

    def delete_credential(self, credential_id: str) -> dict[str, Any]:
        return {"deleted": False, "source": "noop"}

    def generate_selective_disclosure(
        self,
        credential_id: str,
        disclosure_frame: dict[str, Any],
    ) -> dict[str, Any]:
        return {"sd_jwt": "", "source": "noop"}

    def present_credential(
        self,
        credential_id: str,
        presentation_definition: dict[str, Any],
        holder_did: str | None = None,
    ) -> dict[str, Any]:
        return {"presentation": {}, "source": "noop"}

    def health_check(self) -> bool:
        return True
