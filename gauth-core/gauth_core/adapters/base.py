"""Abstract adapter interfaces for proprietary Gimel service extensions.

These interfaces define the extension points where proprietary services
(AI enrichment, risk scoring, regulatory reasoning, compliance, OAuth,
governance, Web3 identity, DNA identity, wallet) can be plugged into
the GAuth Open Core. The core 16-check PEP pipeline is never altered
by adapters — they operate at defined hook points.

Adapters are registered through the AdapterRegistry with trust validation.
Only signed or namespace-verified adapter implementations are accepted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIEnrichmentAdapter(ABC):

    ADAPTER_TYPE = "ai_enrichment"

    @abstractmethod
    def enrich(
        self,
        enforcement_request: dict[str, Any],
        mandate: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class RiskScoringAdapter(ABC):

    ADAPTER_TYPE = "risk_scoring"

    @abstractmethod
    def score(
        self,
        mandate_data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class RegulatoryReasoningAdapter(ABC):

    ADAPTER_TYPE = "regulatory_reasoning"

    @abstractmethod
    def analyze(
        self,
        mandate_data: dict[str, Any],
        regulatory_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class ComplianceEnrichmentAdapter(ABC):

    ADAPTER_TYPE = "compliance_enrichment"

    @abstractmethod
    def evaluate(
        self,
        enforcement_decision: dict[str, Any],
        enforcement_request: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class OAuthEngineAdapter(ABC):

    ADAPTER_TYPE = "oauth_engine"
    IS_MANDATORY_SLOT = True

    @abstractmethod
    def issue_token(
        self,
        grant_type: str,
        client_id: str,
        scope: list[str] | None = None,
        claims: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def validate_token(self, token: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def revoke_token(self, token: str, token_type_hint: str = "access_token") -> dict[str, Any]:
        ...

    @abstractmethod
    def get_jwks(self) -> dict[str, Any]:
        ...

    @abstractmethod
    def introspect(self, token: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def before_token_issuance(self, context: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def after_token_issuance(self, token_response: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class GovernanceAdapter(ABC):

    ADAPTER_TYPE = "governance"

    @abstractmethod
    def evaluate_governance_policy(
        self,
        mandate: dict[str, Any],
        action: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def get_governance_requirements(
        self,
        profile: str,
        sector: str | None = None,
        region: str | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def validate_compliance_state(
        self,
        mandate_id: str,
        current_state: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class Web3IdentityAdapter(ABC):

    ADAPTER_TYPE = "web3_identity"

    @abstractmethod
    def resolve_did(self, did: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def verify_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def create_presentation(
        self,
        credentials: list[dict[str, Any]],
        holder_did: str,
        challenge: str | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def verify_presentation(self, presentation: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class DnaIdentityAdapter(ABC):

    ADAPTER_TYPE = "dna_identity"

    @abstractmethod
    def verify_identity(
        self,
        subject: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def get_identity_assurance_level(
        self,
        subject: str,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def create_identity_binding(
        self,
        subject: str,
        mandate_id: str,
        binding_type: str = "standard",
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...


class WalletAdapter(ABC):

    ADAPTER_TYPE = "wallet"

    @abstractmethod
    def store_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        ...

    @abstractmethod
    def retrieve_credential(self, credential_id: str) -> dict[str, Any] | None:
        ...

    @abstractmethod
    def list_credentials(self, query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        ...

    @abstractmethod
    def delete_credential(self, credential_id: str) -> dict[str, Any]:
        ...

    @abstractmethod
    def generate_selective_disclosure(
        self,
        credential_id: str,
        disclosure_frame: dict[str, Any],
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def present_credential(
        self,
        credential_id: str,
        presentation_definition: dict[str, Any],
        holder_did: str | None = None,
    ) -> dict[str, Any]:
        ...

    @abstractmethod
    def health_check(self) -> bool:
        ...
