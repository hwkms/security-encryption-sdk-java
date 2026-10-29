import os
import struct
import hashlib
import base64
from io import BytesIO

from huaweicloud_encryptionsdk.common.crypto_factory import CryptoFactory


def is_empty(t):
    if t is None:
        return True
    if isinstance(t, (str, list, dict, tuple, set)):
        return len(t) == 0
    return False


def read_master_key(key_paths):
    public_key_list = []
    for path in key_paths:
        try:
            with open(path, "rb") as f:
                data = f.read()
            cleaned = remove_line_symbol(data)
            original_key = base64.b64decode(cleaned)
            public_key_list.append(original_key)
        except FileNotFoundError:
            raise Exception("file not exists:" + os.path.basename(path))
    return public_key_list


def long_to_bytes(num):
    return struct.pack(">q", num)


def bytes_to_long(b):
    return struct.unpack(">q", b)[0]


def bytes_to_int(b):
    return struct.unpack(">i", b)[0]


def add_prevent_overflow(a, b):
    r = a + b
    if a > 0 and b > 0 and r < a:
        return (1 << 63) - 1
    if a < 0 and b < 0 and r > a:
        return -(1 << 63)
    return r


def common_hash(data, alg):
    try:
        md = CryptoFactory.get_message_digest(alg)
        md.update(data)
        return md.digest()
    except Exception:
        raise Exception("message digest error")


def byte_to_string(b):
    if b is None:
        return ""
    return b.decode("utf-8", errors="replace")


def remove_line_symbol(b):
    s = b.decode("utf-8", errors="replace").replace("\r\n", "").replace("\n", "").replace("\\n", "")
    return s.encode("utf-8")


def byte_to_secret_key(b, algorithm):
    return b


def get_public_key(public_key_bytes, alg_flag):
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    try:
        return load_der_public_key(public_key_bytes)
    except Exception as e:
        raise Exception("public key parse exception", e)


def get_private_key(private_key_bytes, alg_flag):
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    try:
        return load_der_private_key(private_key_bytes, password=None)
    except Exception as e:
        raise Exception("private key parse exception", e)


def serialize_context(encryption_context):
    if encryption_context is None or len(encryption_context) == 0:
        return b""
    sorted_items = sorted(encryption_context.items(), key=lambda x: x[1])
    buf = BytesIO()
    buf.write(struct.pack(">h", len(encryption_context)))
    for key, value in sorted_items:
        key_bytes = key.encode("utf-8")
        buf.write(struct.pack(">h", len(key_bytes)))
        buf.write(key_bytes)
        value_bytes = value.encode("utf-8")
        buf.write(struct.pack(">h", len(value_bytes)))
        buf.write(value_bytes)
    return buf.getvalue()


def deserialize_context(data):
    if data is None or len(data) == 0:
        return {}
    buf = BytesIO(data)
    remaining = buf.read(2)
    if len(remaining) < 2:
        raise ValueError("insufficient data for context size")
    context_size = struct.unpack(">h", remaining)[0]
    result = {}
    for _ in range(context_size):
        key_len_data = buf.read(2)
        if len(key_len_data) < 2:
            raise ValueError("insufficient data for key length")
        key_len = struct.unpack(">h", key_len_data)[0]
        key_bytes = buf.read(key_len)
        if len(key_bytes) < key_len:
            raise ValueError("insufficient data for key")
        value_len_data = buf.read(2)
        if len(value_len_data) < 2:
            raise ValueError("insufficient data for value length")
        value_len = struct.unpack(">h", value_len_data)[0]
        value_bytes = buf.read(value_len)
        if len(value_bytes) < value_len:
            raise ValueError("insufficient data for value")
        result[key_bytes.decode("utf-8")] = value_bytes.decode("utf-8")
    return result


def hex_to_bytes(hex_string):
    _HEX_CHARS = set("0123456789abcdefABCDEF")
    if hex_string is None or len(hex_string) == 0 or len(hex_string) % 2 != 0:
        raise ValueError("invalid string length.")
    for c in hex_string:
        if c not in _HEX_CHARS:
            raise ValueError("invalid string char. " + c)
    return bytes.fromhex(hex_string)


def bytes_to_hex(b):
    return b.hex()


def get_capsule_kms_config(kms_config_list, key_capsule_config):
    if is_empty(kms_config_list):
        raise Exception("config null error")
    if key_capsule_config is None:
        raise Exception("KeyCapsuleConfig is required for key capsule mode")
    kms_config = None
    for temp_config in kms_config_list:
        if temp_config.region.lower() == key_capsule_config.region.lower():
            kms_config = temp_config
    if kms_config is None:
        raise Exception("key capsule region not found " + key_capsule_config.region)
    return kms_config
