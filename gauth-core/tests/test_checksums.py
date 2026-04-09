"""Tests for checksum computation."""

from gauth_core.utils.checksums import (
    canonical_json,
    compute_scope_checksum,
    compute_tool_permissions_hash,
    compute_platform_permissions_hash,
)


class TestCanonicalJson:
    def test_sorted_keys(self):
        result = canonical_json({"b": 1, "a": 2})
        assert result.index('"a"') < result.index('"b"')

    def test_deterministic(self):
        obj = {"z": [1, 2, 3], "a": {"nested": True}}
        assert canonical_json(obj) == canonical_json(obj)

    def test_different_key_order_same_output(self):
        a = canonical_json({"b": 1, "a": 2})
        b = canonical_json({"a": 2, "b": 1})
        assert a == b


class TestChecksums:
    def test_scope_checksum_prefix(self):
        result = compute_scope_checksum({"governance_profile": "minimal"})
        assert result.startswith("sha256:")

    def test_same_input_same_hash(self):
        scope = {"governance_profile": "standard", "phase": "build"}
        h1 = compute_scope_checksum(scope)
        h2 = compute_scope_checksum(scope)
        assert h1 == h2

    def test_different_input_different_hash(self):
        h1 = compute_scope_checksum({"governance_profile": "minimal"})
        h2 = compute_scope_checksum({"governance_profile": "strict"})
        assert h1 != h2

    def test_tool_permissions_hash(self):
        verbs = {"file.read": {"allowed": True}, "file.write": {"allowed": False}}
        result = compute_tool_permissions_hash(verbs)
        assert result.startswith("sha256:")

    def test_platform_permissions_hash(self):
        perms = {"auto_deploy": False, "db_write": True}
        result = compute_platform_permissions_hash(perms)
        assert result.startswith("sha256:")
