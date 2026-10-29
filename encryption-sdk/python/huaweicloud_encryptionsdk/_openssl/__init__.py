"""
huaweicloud_encryptionsdk._openssl

华为 OpenSSL 封装层，自动选择最优后端：
  - native C 扩展（1 FFI/操作，优先）
  - ctypes（10-12 FFI/操作，回退）

对外接口不变，调用方无需修改。

公共 API:
  - is_available, supports_sm4_gcm, OpenSSLError
  - Digest, sm3, sha256, new
  - gcm_encrypt/gcm_decrypt, cbc_encrypt/cbc_decrypt
  - aes_gcm_encrypt/decrypt, sm4_gcm_encrypt/decrypt, sm4_cbc_encrypt/decrypt
  - GCM_TAG_LEN, GCM_IV_LEN
  - free_pkey, load_der_private_key, load_der_public_key, load_pem_private_key
  - rsa_encrypt, rsa_decrypt, ecdsa_sign, pkey_get_public_der, extract_ec_private_value
"""
from huaweicloud_encryptionsdk._openssl._library import (
    get_libcrypto, is_available, OpenSSLError, supports_sm4_gcm,
    EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_TAG,
)
from huaweicloud_encryptionsdk._openssl._evp_digest import (
    Digest, sm3, sha256, new,
)
from huaweicloud_encryptionsdk._openssl._evp_cipher import (
    GCM_TAG_LEN, GCM_IV_LEN,
)

# 后端选择：native（1 FFI）→ ctypes（10-12 FFI）
from huaweicloud_encryptionsdk._openssl._backend import get_backend, NATIVE

_backend = get_backend()

if _backend == NATIVE:
    # native C 扩展后端：1 FFI/操作
    from huaweicloud_encryptionsdk._openssl._native_wrapper import (
        gcm_encrypt, gcm_decrypt,
        cbc_encrypt, cbc_decrypt,
        aes_gcm_encrypt, aes_gcm_decrypt,
        sm4_gcm_encrypt, sm4_gcm_decrypt,
        sm4_cbc_encrypt, sm4_cbc_decrypt,
        free_pkey, load_der_private_key, load_der_public_key, load_pem_private_key,
        rsa_encrypt, rsa_decrypt, ecdsa_sign, pkey_get_public_der,
        extract_ec_private_value,
    )
else:
    # ctypes 后端（回退）：10-12 FFI/操作
    from huaweicloud_encryptionsdk._openssl._evp_cipher import (
        gcm_encrypt, gcm_decrypt,
        cbc_encrypt, cbc_decrypt,
        aes_gcm_encrypt, aes_gcm_decrypt,
        sm4_gcm_encrypt, sm4_gcm_decrypt,
        sm4_cbc_encrypt, sm4_cbc_decrypt,
    )
    from huaweicloud_encryptionsdk._openssl._evp_pkey import (
        free_pkey, load_der_private_key, load_der_public_key, load_pem_private_key,
        rsa_encrypt, rsa_decrypt, ecdsa_sign, pkey_get_public_der,
        extract_ec_private_value,
    )

__all__ = [
    "get_libcrypto", "is_available", "OpenSSLError", "supports_sm4_gcm",
    "Digest", "sm3", "sha256", "new",
    "gcm_encrypt", "gcm_decrypt",
    "cbc_encrypt", "cbc_decrypt",
    "aes_gcm_encrypt", "aes_gcm_decrypt",
    "sm4_gcm_encrypt", "sm4_gcm_decrypt",
    "sm4_cbc_encrypt", "sm4_cbc_decrypt",
    "GCM_TAG_LEN", "GCM_IV_LEN",
    "free_pkey", "load_der_private_key", "load_der_public_key", "load_pem_private_key",
    "rsa_encrypt", "rsa_decrypt", "ecdsa_sign", "pkey_get_public_der",
    "extract_ec_private_value",
]
