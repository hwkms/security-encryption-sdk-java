import pytest
from huaweicloud_encryptionsdk.common.utils import (
    is_empty, hex_to_bytes, bytes_to_hex, long_to_bytes, bytes_to_long,
    bytes_to_int, add_prevent_overflow, serialize_context, deserialize_context,
    get_capsule_kms_config,
)
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig
from huaweicloud_encryptionsdk.model.key_capsule_config import KeyCapsuleConfig


class TestIsEmpty:
    def test_none(self):
        assert is_empty(None) is True

    def test_empty_string(self):
        assert is_empty("") is True

    def test_empty_list(self):
        assert is_empty([]) is True

    def test_non_empty_string(self):
        assert is_empty("abc") is False

    def test_non_empty_list(self):
        assert is_empty([1]) is False

    def test_zero(self):
        assert is_empty(0) is True


class TestHexConversion:
    def test_hex_to_bytes(self):
        assert hex_to_bytes("48656c6c6f") == b"Hello"

    def test_bytes_to_hex(self):
        assert bytes_to_hex(b"Hello") == "48656c6c6f"

    def test_roundtrip(self):
        original = b"\x01\x02\xff\x00"
        assert hex_to_bytes(bytes_to_hex(original)) == original

    def test_empty(self):
        with pytest.raises(ValueError):
            hex_to_bytes("")
        assert bytes_to_hex(b"") == ""


class TestLongBytesConversion:
    def test_long_to_bytes(self):
        result = long_to_bytes(256)
        assert len(result) == 8
        assert result[-2:] == b"\x01\x00"

    def test_bytes_to_long(self):
        assert bytes_to_long(long_to_bytes(12345)) == 12345

    def test_bytes_to_int(self):
        b = b"\x00\x00\x00\x2a"
        assert bytes_to_int(b) == 42

    def test_roundtrip(self):
        for val in [0, 1, 255, 256, 65535, 2**31 - 1]:
            assert bytes_to_long(long_to_bytes(val)) == val


class TestAddPreventOverflow:
    def test_normal(self):
        assert add_prevent_overflow(100, 200) == 300

    def test_overflow(self):
        result = add_prevent_overflow(2**63 - 1, 1)
        assert result == 2**63

    def test_zero(self):
        assert add_prevent_overflow(0, 0) == 0


class TestSerializeContext:
    def test_roundtrip(self):
        ctx = {"key1": "value1", "key2": "value2"}
        serialized = serialize_context(ctx)
        deserialized = deserialize_context(serialized)
        assert deserialized == ctx

    def test_empty_context(self):
        ctx = {}
        serialized = serialize_context(ctx)
        deserialized = deserialize_context(serialized)
        assert deserialized == ctx

    def test_single_entry(self):
        ctx = {"a": "b"}
        serialized = serialize_context(ctx)
        deserialized = deserialize_context(serialized)
        assert deserialized == ctx


class TestGetCapsuleKmsConfig:
    def test_found(self):
        kms1 = KMSConfig(region="cn-north-7", key_id="kid1", project_id="pid1")
        kms2 = KMSConfig(region="cn-south-1", key_id="kid2", project_id="pid2")
        kcc = KeyCapsuleConfig(region="cn-north-7")
        result = get_capsule_kms_config([kms1, kms2], kcc)
        assert result.region == "cn-north-7"
        assert result.key_id == "kid1"

    def test_not_found(self):
        kms1 = KMSConfig(region="cn-north-7", key_id="kid1", project_id="pid1")
        kcc = KeyCapsuleConfig(region="cn-south-1")
        with pytest.raises(Exception):
            get_capsule_kms_config([kms1], kcc)
