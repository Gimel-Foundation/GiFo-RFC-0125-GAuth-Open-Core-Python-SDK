"""Adapter registry with trust validation and tariff gate enforcement.

Adapters must be registered through this registry. The registry validates
that adapter implementations come from trusted sources, verifies tariff
gate compliance, and enforces Ed25519 manifest verification for Type C
slots before accepting them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Type

from gauth_core.adapters.base import (
    AIEnrichmentAdapter,
    ComplianceEnrichmentAdapter,
    RegulatoryReasoningAdapter,
    RiskScoringAdapter,
)
from gauth_core.adapters.defaults import (
    NoOpAIEnrichmentAdapter,
    NoOpComplianceEnrichmentAdapter,
    NoOpRegulatoryReasoningAdapter,
    NoOpRiskScoringAdapter,
)
from gauth_core.schema.enums import (
    SLOT_TYPE_CLASSIFICATION,
    TYPE_C_SLOTS,
    Tariff,
    TariffGateResult,
    check_tariff_gate,
)

logger = logging.getLogger(__name__)

ADAPTER_BASE_TYPES: dict[str, type] = {
    "ai_enrichment": AIEnrichmentAdapter,
    "risk_scoring": RiskScoringAdapter,
    "regulatory_reasoning": RegulatoryReasoningAdapter,
    "compliance_enrichment": ComplianceEnrichmentAdapter,
}

NOOP_CLASSES: set[str] = {
    "NoOpAIEnrichmentAdapter",
    "NoOpRiskScoringAdapter",
    "NoOpRegulatoryReasoningAdapter",
    "NoOpComplianceEnrichmentAdapter",
}

SLOT_TO_ADAPTER_TYPE: dict[str, str] = {
    "ai_governance": "ai_enrichment",
    "web3_identity": "risk_scoring",
    "dna_identity": "regulatory_reasoning",
    "pdp": "compliance_enrichment",
}

TRUSTED_NAMESPACES = frozenset({
    "gauth_adapters_gimel",
    "gauth_core.adapters.defaults",
})

GIMEL_MANIFEST_NAMESPACE_PREFIX = "@gimel/"


class AdapterRegistrationError(Exception):
    def __init__(self, message: str, error_code: str = "REGISTRATION_FAILED"):
        self.error_code = error_code
        super().__init__(message)


class ManifestVerificationError(AdapterRegistrationError):
    def __init__(self, message: str, step: str = ""):
        super().__init__(message, error_code="ATTESTATION_REQUIRED")
        self.step = step


def _is_noop(adapter: Any) -> bool:
    return type(adapter).__qualname__ in NOOP_CLASSES


def _is_dev_mode() -> bool:
    return os.environ.get("GAUTH_DEV_MODE", "").lower() == "true"


def _verify_ed25519_manifest(
    slot_name: str,
    adapter: Any,
    manifest: dict[str, Any],
    revoked_keys: set[str] | None = None,
) -> None:
    if not isinstance(manifest, dict):
        raise ManifestVerificationError(
            "Manifest must be a JSON object", step="parse"
        )

    required_fields = {"manifest_version", "adapter_type", "slot_name", "namespace",
                       "issued_at", "expires_at", "public_key", "signature", "checksum"}
    missing = required_fields - set(manifest.keys())
    if missing:
        raise ManifestVerificationError(
            f"Manifest missing required fields: {sorted(missing)}", step="schema_validation"
        )

    if manifest.get("slot_name") != slot_name:
        raise ManifestVerificationError(
            f"Manifest slot_name '{manifest.get('slot_name')}' does not match registration slot '{slot_name}'",
            step="schema_validation",
        )

    now = time.time()
    issued_at = manifest.get("issued_at", 0)
    expires_at = manifest.get("expires_at", 0)
    if isinstance(issued_at, (int, float)) and issued_at > now:
        raise ManifestVerificationError(
            "Manifest issued_at is in the future", step="temporal_validation"
        )
    if isinstance(expires_at, (int, float)) and expires_at < now:
        raise ManifestVerificationError(
            "Manifest has expired", step="temporal_validation"
        )

    namespace = manifest.get("namespace", "")
    if not namespace.startswith(GIMEL_MANIFEST_NAMESPACE_PREFIX):
        raise ManifestVerificationError(
            f"Manifest namespace '{namespace}' must start with '{GIMEL_MANIFEST_NAMESPACE_PREFIX}'",
            step="namespace_validation",
        )

    public_key = manifest.get("public_key", "")
    if revoked_keys and public_key in revoked_keys:
        raise ManifestVerificationError(
            "Manifest public key has been revoked", step="revocation_check"
        )

    signature = manifest.get("signature", "")
    if not signature:
        raise ManifestVerificationError(
            "Manifest signature is empty", step="signature_verification"
        )

    try:
        from nacl.signing import VerifyKey
        from nacl.encoding import HexEncoder
        verify_key = VerifyKey(public_key.encode(), encoder=HexEncoder)
        manifest_copy = {k: v for k, v in manifest.items() if k != "signature"}
        canonical_bytes = json.dumps(manifest_copy, sort_keys=True, separators=(",", ":")).encode()
        verify_key.verify(canonical_bytes, bytes.fromhex(signature))
    except ImportError:
        raise ManifestVerificationError(
            "PyNaCl is not installed — Ed25519 signature verification cannot proceed. "
            "Install PyNaCl (pip install pynacl) for Type C slot registration.",
            step="dependency_check",
        )
    except Exception as exc:
        raise ManifestVerificationError(
            f"Ed25519 signature verification failed: {exc}", step="signature_verification"
        )

    expected_checksum = manifest.get("checksum", "")
    if expected_checksum:
        adapter_module = type(adapter).__module__ or ""
        adapter_qualname = type(adapter).__qualname__
        adapter_id = f"{adapter_module}.{adapter_qualname}"
        actual_checksum = hashlib.sha256(adapter_id.encode()).hexdigest()
        if actual_checksum != expected_checksum:
            raise ManifestVerificationError(
                "Adapter checksum does not match manifest", step="checksum_verification"
            )


class AdapterRegistry:

    def __init__(
        self,
        trusted_namespaces: frozenset[str] | None = None,
        signing_key: bytes | None = None,
        allow_untrusted: bool = False,
        tariff: Tariff = Tariff.O,
        license_token: str | None = None,
        revoked_keys: set[str] | None = None,
    ) -> None:
        self._trusted_namespaces = trusted_namespaces or TRUSTED_NAMESPACES
        self._signing_key = signing_key
        self._tariff = tariff
        self._license_token = self._validate_license_token(license_token)
        self._revoked_keys = revoked_keys or set()
        if allow_untrusted and not _is_dev_mode():
            logger.warning(
                "allow_untrusted=True ignored — GAUTH_DEV_MODE is not set. "
                "Set GAUTH_DEV_MODE=true for development/testing."
            )
            self._allow_untrusted = False
        else:
            self._allow_untrusted = allow_untrusted
        self._adapters: dict[str, Any] = {
            "ai_enrichment": NoOpAIEnrichmentAdapter(),
            "risk_scoring": NoOpRiskScoringAdapter(),
            "regulatory_reasoning": NoOpRegulatoryReasoningAdapter(),
            "compliance_enrichment": NoOpComplianceEnrichmentAdapter(),
        }
        self._audit_log: list[dict[str, Any]] = []

    @staticmethod
    def _validate_license_token(token: str | None) -> str | None:
        if token is None:
            return None
        if not isinstance(token, str) or len(token.strip()) < 16:
            logger.warning(
                "license_token rejected: must be a non-empty string of at least 16 characters"
            )
            return None
        return token.strip()

    @property
    def tariff(self) -> Tariff:
        return self._tariff

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    def _log_audit(self, event: str, details: dict[str, Any]) -> None:
        entry = {"event": event, "timestamp": time.time(), **details}
        self._audit_log.append(entry)
        logger.info("Audit: %s — %s", event, details)

    def _is_trusted_namespace(self, adapter: Any) -> bool:
        module = type(adapter).__module__ or ""
        return any(module.startswith(ns) for ns in self._trusted_namespaces)

    def _verify_signature(self, adapter: Any, signature: bytes) -> bool:
        if not self._signing_key:
            return False
        adapter_id = f"{type(adapter).__module__}.{type(adapter).__qualname__}"
        expected = hmac.new(self._signing_key, adapter_id.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    def _get_slot_name_for_adapter_type(self, adapter_type: str) -> str:
        reverse_map = {v: k for k, v in SLOT_TO_ADAPTER_TYPE.items()}
        return reverse_map.get(adapter_type, adapter_type)

    def register(
        self,
        adapter: Any,
        adapter_type: str | None = None,
        signature: bytes | None = None,
        manifest: dict[str, Any] | None = None,
        force: bool = False,
    ) -> None:
        if adapter_type is None:
            adapter_type = getattr(adapter, "ADAPTER_TYPE", None)
            if adapter_type is None:
                raise AdapterRegistrationError(
                    "Adapter must have ADAPTER_TYPE attribute or adapter_type must be provided"
                )

        if adapter_type not in ADAPTER_BASE_TYPES:
            raise AdapterRegistrationError(f"Unknown adapter type: {adapter_type}")

        base_type = ADAPTER_BASE_TYPES[adapter_type]
        if not isinstance(adapter, base_type):
            raise AdapterRegistrationError(
                f"Adapter must be an instance of {base_type.__name__}"
            )

        effective_slot = self._get_slot_name_for_adapter_type(adapter_type)

        if force:
            if not self._license_token:
                self._log_audit("registration_rejected", {
                    "adapter_type": adapter_type,
                    "slot": effective_slot,
                    "reason": "force=True requires a valid license token",
                    "error_code": "LICENSE_REQUIRED",
                })
                raise AdapterRegistrationError(
                    "force=True requires a valid Gimel license token. "
                    "Provide license_token to the registry constructor.",
                    error_code="LICENSE_REQUIRED",
                )

        gate = check_tariff_gate(effective_slot, self._tariff)
        if not gate.allowed and not _is_noop(adapter):
            self._log_audit("registration_rejected", {
                "adapter_type": adapter_type,
                "slot": effective_slot,
                "tariff": self._tariff.value,
                "reason": gate.reason,
                "error_code": "TARIFF_GATE_DENIED",
            })
            raise AdapterRegistrationError(
                f"Tariff gate denied: {gate.reason}",
                error_code="TARIFF_GATE_DENIED",
            )

        if effective_slot in TYPE_C_SLOTS and not _is_noop(adapter):
            if manifest is None:
                self._log_audit("registration_rejected", {
                    "adapter_type": adapter_type,
                    "slot": effective_slot,
                    "reason": "Type C slot requires Ed25519 signed manifest",
                    "error_code": "ATTESTATION_REQUIRED",
                })
                raise AdapterRegistrationError(
                    "Type C slot registration requires an Ed25519 signed manifest. "
                    "Provide a manifest parameter with a valid signed manifest.",
                    error_code="ATTESTATION_REQUIRED",
                )
            _verify_ed25519_manifest(
                effective_slot, adapter, manifest, self._revoked_keys
            )

        trusted = self._is_trusted_namespace(adapter)

        if not trusted and signature is not None:
            trusted = self._verify_signature(adapter, signature)

        if not trusted and not self._allow_untrusted and not (force and self._license_token):
            raise AdapterRegistrationError(
                f"Adapter from module '{type(adapter).__module__}' is not from a trusted namespace. "
                f"Trusted namespaces: {sorted(self._trusted_namespaces)}. "
                "Provide a valid signature or set GAUTH_DEV_MODE=true for development.",
                error_code="REGISTRATION_FAILED",
            )

        if not trusted:
            logger.warning(
                "Registering untrusted adapter %s.%s for slot '%s'",
                type(adapter).__module__,
                type(adapter).__qualname__,
                adapter_type,
            )

        self._adapters[adapter_type] = adapter
        self._log_audit("adapter_registered", {
            "adapter_type": adapter_type,
            "slot": effective_slot,
            "adapter_class": type(adapter).__qualname__,
            "tariff": self._tariff.value,
            "trusted": trusted,
        })
        logger.info("Registered adapter for '%s': %s", adapter_type, type(adapter).__qualname__)

    def change_tariff(self, new_tariff: Tariff) -> list[dict[str, Any]]:
        old_tariff = self._tariff
        self._tariff = new_tariff
        deactivated: list[dict[str, Any]] = []

        defaults = {
            "ai_enrichment": NoOpAIEnrichmentAdapter,
            "risk_scoring": NoOpRiskScoringAdapter,
            "regulatory_reasoning": NoOpRegulatoryReasoningAdapter,
            "compliance_enrichment": NoOpComplianceEnrichmentAdapter,
        }

        for adapter_type, adapter in list(self._adapters.items()):
            if _is_noop(adapter):
                continue
            slot = self._get_slot_name_for_adapter_type(adapter_type)
            gate = check_tariff_gate(slot, new_tariff)
            if not gate.allowed:
                noop_cls = defaults.get(adapter_type)
                if noop_cls:
                    self._adapters[adapter_type] = noop_cls()
                event = {
                    "adapter_type": adapter_type,
                    "slot": slot,
                    "old_tariff": old_tariff.value,
                    "new_tariff": new_tariff.value,
                    "deactivated_class": type(adapter).__qualname__,
                    "reason": gate.reason,
                }
                deactivated.append(event)
                self._log_audit("adapter_deactivated_tariff_downgrade", event)

        self._log_audit("tariff_changed", {
            "old_tariff": old_tariff.value,
            "new_tariff": new_tariff.value,
            "deactivated_count": len(deactivated),
        })
        return deactivated

    def validate_tariff_compliance(self) -> list[dict[str, Any]]:
        violations: list[dict[str, Any]] = []
        for adapter_type, adapter in self._adapters.items():
            if _is_noop(adapter):
                continue
            slot = self._get_slot_name_for_adapter_type(adapter_type)
            gate = check_tariff_gate(slot, self._tariff)
            if not gate.allowed:
                violation = {
                    "adapter_type": adapter_type,
                    "slot": slot,
                    "tariff": self._tariff.value,
                    "adapter_class": type(adapter).__qualname__,
                    "reason": gate.reason,
                    "error_code": "LICENSE_COMPLIANCE_VIOLATION",
                }
                violations.append(violation)
                self._log_audit("license_compliance_violation", violation)
                logger.warning(
                    "LICENSE_COMPLIANCE_VIOLATION: Non-NoOp adapter '%s' in slot '%s' "
                    "is not permitted on tariff %s. Adapter will be treated as NoOp.",
                    type(adapter).__qualname__, slot, self._tariff.value,
                )
        return violations

    def is_adapter_compliant(self, adapter_type: str) -> bool:
        adapter = self._adapters.get(adapter_type)
        if adapter is None or _is_noop(adapter):
            return True
        slot = self._get_slot_name_for_adapter_type(adapter_type)
        gate = check_tariff_gate(slot, self._tariff)
        return gate.allowed

    @property
    def ai_enrichment(self) -> AIEnrichmentAdapter:
        return self._adapters["ai_enrichment"]

    @property
    def risk_scoring(self) -> RiskScoringAdapter:
        return self._adapters["risk_scoring"]

    @property
    def regulatory_reasoning(self) -> RegulatoryReasoningAdapter:
        return self._adapters["regulatory_reasoning"]

    @property
    def compliance_enrichment(self) -> ComplianceEnrichmentAdapter:
        return self._adapters["compliance_enrichment"]

    def get(self, adapter_type: str) -> Any:
        if adapter_type not in self._adapters:
            raise KeyError(f"No adapter registered for type: {adapter_type}")
        return self._adapters[adapter_type]

    def list_registered(self) -> dict[str, str]:
        return {
            k: type(v).__qualname__
            for k, v in self._adapters.items()
        }
