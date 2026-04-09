"""SHA-256 checksum computation using canonical JSON serialization."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    if isinstance(obj, dict):
        items = sorted(
            (k, canonical_json(v)) for k, v in obj.items()
        )
        return "{" + ",".join(f"{json.dumps(k)}:{v}" for k, v in items) + "}"
    elif isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in obj) + "]"
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif obj is None:
        return "null"
    elif isinstance(obj, (int, float)):
        return json.dumps(obj)
    elif isinstance(obj, str):
        return json.dumps(obj)
    else:
        return json.dumps(str(obj))


def _sha256_hex(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_scope_checksum(scope: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(scope))


def compute_tool_permissions_hash(core_verbs: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(core_verbs))


def compute_platform_permissions_hash(platform_permissions: dict[str, Any]) -> str:
    return _sha256_hex(canonical_json(platform_permissions))
