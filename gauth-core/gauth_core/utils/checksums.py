"""SHA-256 checksum computation using RFC 8785 JCS-compatible canonical JSON.

Implements JSON Canonicalization Scheme (RFC 8785) rules:
- Object keys are sorted lexicographically by Unicode code point
- No whitespace between tokens
- Strings use JSON escape sequences (via json.dumps)
- Numbers serialized per ES2015 Number-to-String (json.dumps default)
- Booleans as ``true``/``false``; null as ``null``
- Recursion into nested objects and arrays
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    if isinstance(obj, dict):
        items = sorted(
            (k, canonical_json(v)) for k, v in obj.items()
        )
        return "{" + ",".join(f"{json.dumps(k, ensure_ascii=False)}:{v}" for k, v in items) + "}"
    elif isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in obj) + "]"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif obj is None:
        return "null"
    elif isinstance(obj, int):
        return str(obj)
    elif isinstance(obj, float):
        if obj == 0.0:
            return "0"
        if obj != obj:
            raise ValueError("NaN is not allowed in canonical JSON (RFC 8785)")
        if obj == float("inf") or obj == float("-inf"):
            raise ValueError("Infinity is not allowed in canonical JSON (RFC 8785)")
        return json.dumps(obj)
    elif isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    else:
        return json.dumps(str(obj), ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_scope_checksum(scope: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(scope))


def compute_tool_permissions_hash(core_verbs: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(core_verbs))


def compute_platform_permissions_hash(platform_permissions: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(platform_permissions))
