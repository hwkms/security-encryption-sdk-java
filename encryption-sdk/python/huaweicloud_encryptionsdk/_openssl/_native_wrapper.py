"""native C 扩展包装层：将 1-FFI 原始接口适配为 SDK 公共 API。

C 扩展返回 ct||tag 连续 bytes，本模块拆分为 (ct, tag) 元组以匹配现有 API。
abi3 模式下 "y#" 只接受 bytes，不接受 bytearray，用 _b() 统一转换。
"""
from huaweicloud_encryptionsdk._openssl._backend import _get_native_core
from huaweicloud_encryptionsdk._openssl._library import OpenSSLError

_native_core = _get_native_core()
GCM_TAG_LEN = 16


def _b(data):
    """bytearray/memoryview -> bytes（abi3 的 "y#" 不接受 bytearray）。"""
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return data


# ── GCM ──────────────────────────────────────────────────

def aes_gcm_encrypt(key, iv, plaintext, aad=b"", tag_len=GCM_TAG_LEN):
    """AES-GCM 加密，返回 (ciphertext, tag)。"""
    if tag_len != 16:
        from huaweicloud_encryptionsdk._openssl._evp_cipher import aes_gcm_encrypt as _ct
        return _ct(key, iv, plaintext, aad, tag_len)
    raw = _native_core.aes_gcm_encrypt(_b(key), _b(iv), _b(aad), _b(plaintext))
    return raw[:-16], raw[-16:]


def aes_gcm_decrypt(key, iv, ciphertext, tag, aad=b""):
    """AES-GCM 解密。"""
    return _native_core.aes_gcm_decrypt(_b(key), _b(iv), _b(aad), _b(ciphertext) + _b(tag))


def sm4_gcm_encrypt(key, iv, plaintext, aad=b"", tag_len=GCM_TAG_LEN):
    """SM4-GCM 加密，返回 (ciphertext, tag)。"""
    if tag_len != 16:
        from huaweicloud_encryptionsdk._openssl._evp_cipher import sm4_gcm_encrypt as _ct
        return _ct(key, iv, plaintext, aad, tag_len)
    raw = _native_core.sm4_gcm_encrypt(_b(key), _b(iv), _b(aad), _b(plaintext))
    return raw[:-16], raw[-16:]


def sm4_gcm_decrypt(key, iv, ciphertext, tag, aad=b""):
    """SM4-GCM 解密。"""
    return _native_core.sm4_gcm_decrypt(_b(key), _b(iv), _b(aad), _b(ciphertext) + _b(tag))


# ── CBC ──────────────────────────────────────────────────

def sm4_cbc_encrypt(key, iv, plaintext):
    """SM4-CBC 加密（PKCS7 padding）。"""
    return _native_core.sm4_cbc_encrypt(_b(key), _b(iv), _b(plaintext))


def sm4_cbc_decrypt(key, iv, ciphertext):
    """SM4-CBC 解密（PKCS7 unpadding）。"""
    return _native_core.sm4_cbc_decrypt(_b(key), _b(iv), _b(ciphertext))


# ── RSA ──────────────────────────────────────────────────

def rsa_encrypt(pub_der, plaintext):
    """RSA-OAEP-SHA256 加密。"""
    return _native_core.rsa_encrypt(_b(pub_der), _b(plaintext))


def rsa_decrypt(priv_der, ciphertext):
    """RSA-OAEP-SHA256 解密。"""
    return _native_core.rsa_decrypt(_b(priv_der), _b(ciphertext))


# ── 密钥加载 ─────────────────────────────────────────────

def load_der_private_key(der_bytes):
    """加载 DER 私钥，返回 EVP_PKEY 指针（int）。"""
    return _native_core.load_der_private_key(_b(der_bytes))


def load_der_public_key(der_bytes):
    """加载 DER 公钥，返回 EVP_PKEY 指针（int）。"""
    return _native_core.load_der_public_key(_b(der_bytes))


def load_pem_private_key(pem_bytes):
    """加载 PEM 私钥，返回 EVP_PKEY 指针（int）。"""
    return _native_core.load_pem_private_key(_b(pem_bytes))


def free_pkey(pkey):
    """释放 EVP_PKEY。"""
    if pkey:
        _native_core.free_pkey(pkey)


# ── ECDSA / 公钥导出 ─────────────────────────────────────

def ecdsa_sign(priv_pkey, message):
    """ECDSA-SHA256 签名，返回 DER 编码签名。"""
    return _native_core.ecdsa_sign(priv_pkey, _b(message))


def pkey_get_public_der(priv_pkey):
    """从私钥提取公钥 SubjectPublicKeyInfo DER。"""
    return _native_core.pkey_get_public_der(priv_pkey)


def extract_ec_private_value(der_bytes):
    """从 PKCS#8 DER EC 私钥提取私钥标量值（int）。"""
    return _native_core.extract_ec_private_value(_b(der_bytes))


# ── 通用 GCM/CBC（cipher_name 路由）──────────────────────

def gcm_encrypt(cipher_name, key, iv, plaintext, aad=b"", tag_len=GCM_TAG_LEN):
    """通用 GCM 加密，按 cipher_name 路由。"""
    if cipher_name.startswith("AES"):
        return aes_gcm_encrypt(key, iv, plaintext, aad, tag_len)
    elif cipher_name == "SM4-GCM":
        return sm4_gcm_encrypt(key, iv, plaintext, aad, tag_len)
    else:
        raise OpenSSLError("unsupported cipher: %s" % cipher_name)


def gcm_decrypt(cipher_name, key, iv, ciphertext, tag, aad=b""):
    """通用 GCM 解密，按 cipher_name 路由。"""
    if cipher_name.startswith("AES"):
        return aes_gcm_decrypt(key, iv, ciphertext, tag, aad)
    elif cipher_name == "SM4-GCM":
        return sm4_gcm_decrypt(key, iv, ciphertext, tag, aad)
    else:
        raise OpenSSLError("unsupported cipher: %s" % cipher_name)


def cbc_encrypt(cipher_name, key, iv, plaintext):
    """通用 CBC 加密，按 cipher_name 路由。"""
    if cipher_name == "SM4-CBC":
        return sm4_cbc_encrypt(key, iv, plaintext)
    raise OpenSSLError("unsupported cipher: %s" % cipher_name)


def cbc_decrypt(cipher_name, key, iv, ciphertext):
    """通用 CBC 解密，按 cipher_name 路由。"""
    if cipher_name == "SM4-CBC":
        return sm4_cbc_decrypt(key, iv, ciphertext)
    raise OpenSSLError("unsupported cipher: %s" % cipher_name)
