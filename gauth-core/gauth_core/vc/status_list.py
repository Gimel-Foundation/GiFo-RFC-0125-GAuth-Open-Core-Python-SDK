"""Bitstring Status List v2.0 — Gap Spec G-07 Step 5."""

from __future__ import annotations

import base64
import time
import zlib
from typing import Any


class BitstringStatusList:

    def __init__(
        self,
        size: int = 131072,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._size = size
        self._bitstring = bytearray(size // 8)
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._revocation_reasons: dict[int, str] = {}

    @property
    def size(self) -> int:
        return self._size

    def set_status(self, index: int, revoked: bool, reason: str = "") -> None:
        if index < 0 or index >= self._size:
            raise ValueError(f"Index {index} out of range [0, {self._size})")
        byte_index = index // 8
        bit_index = index % 8
        if revoked:
            self._bitstring[byte_index] |= (1 << (7 - bit_index))
            if reason:
                self._revocation_reasons[index] = reason
        else:
            self._bitstring[byte_index] &= ~(1 << (7 - bit_index))
            self._revocation_reasons.pop(index, None)

    def get_status(self, index: int) -> bool:
        if index < 0 or index >= self._size:
            raise ValueError(f"Index {index} out of range [0, {self._size})")
        byte_index = index // 8
        bit_index = index % 8
        return bool(self._bitstring[byte_index] & (1 << (7 - bit_index)))

    def get_revocation_reason(self, index: int) -> str:
        return self._revocation_reasons.get(index, "")

    def encode(self) -> str:
        compressed = zlib.compress(bytes(self._bitstring))
        return base64.urlsafe_b64encode(compressed).decode()

    @classmethod
    def decode(cls, encoded: str, size: int = 131072) -> "BitstringStatusList":
        compressed = base64.urlsafe_b64decode(encoded)
        raw = zlib.decompress(compressed)
        sl = cls(size=size)
        sl._bitstring = bytearray(raw[:size // 8])
        return sl

    def to_status_list_credential(
        self,
        credential_id: str,
        issuer_did: str,
    ) -> dict[str, Any]:
        return {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/vc/status-list/2021/v1",
            ],
            "id": credential_id,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": {"id": issuer_did},
            "credentialSubject": {
                "id": f"{credential_id}#list",
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": self.encode(),
            },
        }

    def check_revocation(
        self,
        status_entry: dict[str, Any],
    ) -> dict[str, Any]:
        index = status_entry.get("statusListIndex", 0)
        credential_url = status_entry.get("statusListCredential", "")

        cached = self._cache.get(credential_url)
        if cached:
            cache_time, cache_result = cached
            if time.time() - cache_time < self._cache_ttl:
                revoked = self.get_status(index)
                return {
                    "revoked": revoked,
                    "index": index,
                    "reason": self.get_revocation_reason(index) if revoked else "",
                    "cached": True,
                    "credential_url": credential_url,
                }

        revoked = self.get_status(index)
        result = {
            "revoked": revoked,
            "index": index,
            "reason": self.get_revocation_reason(index) if revoked else "",
            "cached": False,
            "credential_url": credential_url,
        }

        self._cache[credential_url] = (time.time(), result)
        return result
