"""
EVP 对称加密: AES-GCM, SM4-GCM, SM4-CBC

接口设计:
  gcm_encrypt(key, iv, plaintext, aad) -> (ciphertext, tag)
  gcm_decrypt(key, iv, ciphertext, tag, aad) -> plaintext
  cbc_encrypt(key, iv, plaintext) -> ciphertext  (PKCS7 padding)
  cbc_decrypt(key, iv, ciphertext) -> plaintext  (PKCS7 unpadding)
"""
import ctypes

from huaweicloud_encryptionsdk._openssl._library import (
    get_libcrypto, EVP_SUCCESS,
    EVP_CTRL_GCM_SET_IVLEN, EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_TAG,
    OpenSSLError,
)

# 默认 GCM tag 长度
GCM_TAG_LEN = 16
# 默认 GCM IV 长度
GCM_IV_LEN = 12


def _b(data):
    """bytearray/memoryview -> bytes (ctypes c_char_p 只接受 bytes)"""
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return data


# ── GCM ────────────────────────────────────────────────

def gcm_encrypt(cipher_name: str, key: bytes, iv: bytes,
                plaintext: bytes, aad: bytes = b"", tag_len: int = GCM_TAG_LEN):
    """
    GCM 加密
    :param cipher_name: "AES-128-GCM", "AES-256-GCM", "SM4-GCM"
    :param key: 密钥
    :param iv: 初始化向量 (通常 12 字节)
    :param plaintext: 明文
    :param aad: 附加认证数据 (authenticated but not encrypted)
    :param tag_len: tag 长度 (默认 16)
    :return: (ciphertext, tag)
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行加密操作。请检查 libcrypto.so 是否正确安装。")

    key = _b(key); iv = _b(iv); plaintext = _b(plaintext); aad = _b(aad)

    # SM4-GCM 仅 OpenSSL 3.x 支持
    if cipher_name == "SM4-GCM" and not lc.supports_sm4_gcm():
        raise OpenSSLError(
            "SM4-GCM 需要 OpenSSL 3.1+，当前版本为 %s。请安装华为 OpenSSL 3.x。" % lc.version()
        )

    cipher = lc.fetch_cipher(cipher_name.encode())
    if not cipher:
        raise OpenSSLError("fetch_cipher(%s) 失败" % cipher_name)

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        lc.free_cipher(cipher)
        raise OpenSSLError("EVP_CIPHER_CTX_new 失败")

    try:
        # 1. 初始化 cipher (不传 key/iv)
        if lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptInit_ex (cipher) 失败")

        # 2. 设置 IV 长度
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != EVP_SUCCESS:
            raise OpenSSLError("EVP_CIPHER_CTX_ctrl (SET_IVLEN) 失败")

        # 3. 设置 key + iv
        if lib.EVP_EncryptInit_ex(ctx, None, None, key, iv) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptInit_ex (key/iv) 失败")

        # 4. AAD (输出缓冲区必须为 NULL)
        if aad:
            aad_outlen = ctypes.c_int(0)
            if lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(aad_outlen), aad, len(aad)) != EVP_SUCCESS:
                raise OpenSSLError("EVP_EncryptUpdate (AAD) 失败")

        # 5. 加密明文
        ct_buf = ctypes.create_string_buffer(len(plaintext) + 16)
        ct_len = ctypes.c_int(0)
        if lib.EVP_EncryptUpdate(ctx, ct_buf, ctypes.byref(ct_len), plaintext, len(plaintext)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptUpdate (plaintext) 失败")

        # 6. Finalize (GCM 末尾输出 0 字节)
        final_buf = ctypes.create_string_buffer(16)
        final_len = ctypes.c_int(0)
        if lib.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptFinal_ex 失败")

        ciphertext = ct_buf.raw[:ct_len.value] + final_buf.raw[:final_len.value]

        # 7. 获取 tag
        tag = ctypes.create_string_buffer(tag_len)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != EVP_SUCCESS:
            raise OpenSSLError("EVP_CIPHER_CTX_ctrl (GET_TAG) 失败")

        return ciphertext, tag.raw[:tag_len]

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lc.free_cipher(cipher)


def gcm_decrypt(cipher_name: str, key: bytes, iv: bytes,
                ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """
    GCM 解密
    :param cipher_name: "AES-128-GCM", "AES-256-GCM", "SM4-GCM"
    :param key: 密钥
    :param iv: 初始化向量
    :param ciphertext: 密文 (不含 tag)
    :param tag: 认证 tag
    :param aad: 附加认证数据
    :return: 明文
    :raises OpenSSLError: tag 验证失败
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 %s 解密" % cipher_name)

    key = _b(key); iv = _b(iv); ciphertext = _b(ciphertext); tag = _b(tag); aad = _b(aad)

    # SM4-GCM 仅 OpenSSL 3.x 支持
    if cipher_name == "SM4-GCM" and not lc.supports_sm4_gcm():
        raise OpenSSLError(
            "SM4-GCM 需要 OpenSSL 3.1+，当前版本为 %s。请安装华为 OpenSSL 3.x。" % lc.version()
        )

    cipher = lc.fetch_cipher(cipher_name.encode())
    if not cipher:
        raise OpenSSLError("fetch_cipher(%s) 失败" % cipher_name)

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        lc.free_cipher(cipher)
        raise OpenSSLError("EVP_CIPHER_CTX_new 失败")

    try:
        # 1. 初始化 cipher
        if lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DecryptInit_ex (cipher) 失败")

        # 2. 设置 IV 长度
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != EVP_SUCCESS:
            raise OpenSSLError("EVP_CIPHER_CTX_ctrl (SET_IVLEN) 失败")

        # 3. 设置 key + iv
        if lib.EVP_DecryptInit_ex(ctx, None, None, key, iv) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DecryptInit_ex (key/iv) 失败")

        # 4. AAD (输出缓冲区必须为 NULL)
        if aad:
            aad_outlen = ctypes.c_int(0)
            if lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(aad_outlen), aad, len(aad)) != EVP_SUCCESS:
                raise OpenSSLError("EVP_DecryptUpdate (AAD) 失败")

        # 5. 解密密文
        pt_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        pt_len = ctypes.c_int(0)
        if lib.EVP_DecryptUpdate(ctx, pt_buf, ctypes.byref(pt_len), ciphertext, len(ciphertext)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DecryptUpdate (ciphertext) 失败")

        # 6. 设置 tag (在 Final 之前)
        tag_buf = ctypes.create_string_buffer(tag, len(tag))
        if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), tag_buf) != EVP_SUCCESS:
            raise OpenSSLError("EVP_CIPHER_CTX_ctrl (SET_TAG) 失败")

        # 7. Finalize (验证 tag)
        final_buf = ctypes.create_string_buffer(16)
        final_len = ctypes.c_int(0)
        if lib.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != EVP_SUCCESS:
            raise OpenSSLError("GCM tag 验证失败")

        return pt_buf.raw[:pt_len.value] + final_buf.raw[:final_len.value]

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lc.free_cipher(cipher)


# ── CBC (PKCS7 padding) ────────────────────────────────

def cbc_encrypt(cipher_name: str, key: bytes, iv: bytes, plaintext: bytes):
    """
    CBC 加密 (自动 PKCS7 padding)
    :param cipher_name: "SM4-CBC", "AES-128-CBC", "AES-256-CBC"
    :param key: 密钥
    :param iv: 初始化向量 (16 字节)
    :param plaintext: 明文
    :return: 密文 (含 padding)
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 %s 加密" % cipher_name)

    key = _b(key); iv = _b(iv); plaintext = _b(plaintext)

    cipher = lc.fetch_cipher(cipher_name.encode())
    if not cipher:
        raise OpenSSLError("fetch_cipher(%s) 失败" % cipher_name)

    block_size = lc.cipher_block_size(cipher)
    if block_size <= 0:
        block_size = 16

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        lc.free_cipher(cipher)
        raise OpenSSLError("EVP_CIPHER_CTX_new 失败")

    try:
        if lib.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptInit_ex 失败")

        ct_buf = ctypes.create_string_buffer(len(plaintext) + block_size)
        ct_len = ctypes.c_int(0)
        if lib.EVP_EncryptUpdate(ctx, ct_buf, ctypes.byref(ct_len), plaintext, len(plaintext)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptUpdate 失败")

        final_buf = ctypes.create_string_buffer(block_size)
        final_len = ctypes.c_int(0)
        if lib.EVP_EncryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_EncryptFinal_ex 失败")

        return ct_buf.raw[:ct_len.value] + final_buf.raw[:final_len.value]

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lc.free_cipher(cipher)


def cbc_decrypt(cipher_name: str, key: bytes, iv: bytes, ciphertext: bytes):
    """
    CBC 解密 (自动 PKCS7 unpadding)
    :param cipher_name: "SM4-CBC", "AES-128-CBC", "AES-256-CBC"
    :param key: 密钥
    :param iv: 初始化向量 (16 字节)
    :param ciphertext: 密文 (含 padding)
    :return: 明文
    :raises OpenSSLError: padding 错误
    """
    lc = get_libcrypto()
    lib = lc.lib

    if lib is None:
        raise OpenSSLError("华为 OpenSSL 不可用，无法执行 %s 解密" % cipher_name)

    key = _b(key); iv = _b(iv); ciphertext = _b(ciphertext)

    cipher = lc.fetch_cipher(cipher_name.encode())
    if not cipher:
        raise OpenSSLError("fetch_cipher(%s) 失败" % cipher_name)

    block_size = lc.cipher_block_size(cipher)
    if block_size <= 0:
        block_size = 16

    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        lc.free_cipher(cipher)
        raise OpenSSLError("EVP_CIPHER_CTX_new 失败")

    try:
        if lib.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DecryptInit_ex 失败")

        pt_buf = ctypes.create_string_buffer(len(ciphertext) + block_size)
        pt_len = ctypes.c_int(0)
        if lib.EVP_DecryptUpdate(ctx, pt_buf, ctypes.byref(pt_len), ciphertext, len(ciphertext)) != EVP_SUCCESS:
            raise OpenSSLError("EVP_DecryptUpdate 失败")

        final_buf = ctypes.create_string_buffer(block_size)
        final_len = ctypes.c_int(0)
        if lib.EVP_DecryptFinal_ex(ctx, final_buf, ctypes.byref(final_len)) != EVP_SUCCESS:
            raise OpenSSLError("CBC padding 错误")

        return pt_buf.raw[:pt_len.value] + final_buf.raw[:final_len.value]

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
        lc.free_cipher(cipher)


# ── 算法专用便捷函数 ───────────────────────────────────

def aes_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = GCM_TAG_LEN):
    """AES-GCM 加密 (自动选择 128/256)"""
    cipher_name = "AES-%d-GCM" % (len(key) * 8)
    return gcm_encrypt(cipher_name, key, iv, plaintext, aad, tag_len)


def aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """AES-GCM 解密 (自动选择 128/256)"""
    cipher_name = "AES-%d-GCM" % (len(key) * 8)
    return gcm_decrypt(cipher_name, key, iv, ciphertext, tag, aad)


def sm4_gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = GCM_TAG_LEN):
    """SM4-GCM 加密"""
    return gcm_encrypt("SM4-GCM", key, iv, plaintext, aad, tag_len)


def sm4_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""):
    """SM4-GCM 解密"""
    return gcm_decrypt("SM4-GCM", key, iv, ciphertext, tag, aad)


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    """SM4-CBC 加密 (PKCS7 padding)"""
    return cbc_encrypt("SM4-CBC", key, iv, plaintext)


def sm4_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    """SM4-CBC 解密 (PKCS7 unpadding)"""
    return cbc_decrypt("SM4-CBC", key, iv, ciphertext)
