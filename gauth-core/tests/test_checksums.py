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


    def test_nested_key_order_determinism(self):
        a = canonical_json({"x": {"z": 1, "a": 2}, "m": [3, {"b": 4, "a": 5}]})
        b = canonical_json({"m": [3, {"a": 5, "b": 4}], "x": {"a": 2, "z": 1}})
        assert a == b

    def test_rfc8785_nan_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="NaN"):
            canonical_json(float("nan"))

    def test_rfc8785_infinity_rejected(self):
        import pytest
        with pytest.raises(ValueError, match="Infinity"):
            canonical_json(float("inf"))

    def test_integer_zero(self):
        assert canonical_json(0) == "0"

    def test_float_zero(self):
        assert canonical_json(0.0) == "0"


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
