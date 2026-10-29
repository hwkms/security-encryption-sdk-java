"""
SM4-GCM 专项调试: 定位 tag 验证失败的原因
测试变量: 有/无 AAD, tag 打印, cast 方式
"""
import ctypes
import os

EVP_CTRL_GCM_SET_IVLEN = 0x09
EVP_CTRL_GCM_GET_TAG   = 0x10
EVP_CTRL_GCM_SET_TAG   = 0x11

lib = ctypes.CDLL("/opt/huawei-openssl/lib/libcrypto.so")

# 函数签名
lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
lib.EVP_EncryptInit_ex.restype = ctypes.c_int
lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_EncryptUpdate.restype = ctypes.c_int
lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
lib.EVP_DecryptInit_ex.restype = ctypes.c_int
lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_DecryptUpdate.restype = ctypes.c_int
lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]


def sm4_gcm_test(label, use_aad=True, use_cast=False):
    print("\n--- %s ---" % label)
    cipher = lib.EVP_CIPHER_fetch(None, b"SM4-GCM", None)
    if not cipher:
        print("  [FAIL] fetch SM4-GCM")
        return False

    key = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    iv = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc"
    aad = b"auth data" if use_aad else None
    plaintext = b"SM4-GCM test payload!!"  # 22 bytes

    # ── 加密 ──
    ctx = lib.EVP_CIPHER_CTX_new()
    lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)

    if use_aad:
        aad_outlen = ctypes.c_int(0)
        lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(aad_outlen), aad, len(aad))
        print("  encrypt AAD outlen=%d (expected 0)" % aad_outlen.value)

    ctbuf = ctypes.create_string_buffer(len(plaintext) + 32)
    ctlen = ctypes.c_int(0)
    lib.EVP_EncryptUpdate(ctx, ctbuf, ctypes.byref(ctlen), plaintext, len(plaintext))
    print("  encrypt Update outlen=%d (expected %d)" % (ctlen.value, len(plaintext)))

    finalbuf = ctypes.create_string_buffer(32)
    finallen = ctypes.c_int(0)
    lib.EVP_EncryptFinal_ex(ctx, finalbuf, ctypes.byref(finallen))
    print("  encrypt Final outlen=%d (expected 0)" % finallen.value)

    ciphertext = ctbuf.raw[:ctlen.value] + finalbuf.raw[:finallen.value]

    # Get tag
    tag = ctypes.create_string_buffer(16)
    if use_cast:
        ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ctypes.cast(tag, ctypes.c_void_p))
    else:
        ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)
    print("  GET_TAG ret=%d, tag=%s" % (ret, tag.raw[:16].hex()))
    lib.EVP_CIPHER_CTX_free(ctx)

    # ── 解密 ──
    ctx = lib.EVP_CIPHER_CTX_new()
    lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    lib.EVP_DecryptInit_ex(ctx, None, None, key, iv)

    if use_aad:
        aad_outlen_d = ctypes.c_int(0)
        lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(aad_outlen_d), aad, len(aad))
        print("  decrypt AAD outlen=%d (expected 0)" % aad_outlen_d.value)

    ptbuf = ctypes.create_string_buffer(len(ciphertext) + 32)
    ptlen = ctypes.c_int(0)
    lib.EVP_DecryptUpdate(ctx, ptbuf, ctypes.byref(ptlen), ciphertext, len(ciphertext))
    print("  decrypt Update outlen=%d (expected %d)" % (ptlen.value, len(plaintext)))

    # Set tag
    if use_cast:
        ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ctypes.cast(tag, ctypes.c_void_p))
    else:
        ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
    print("  SET_TAG ret=%d" % ret)

    # Final
    finalbuf_d = ctypes.create_string_buffer(32)
    finallen_d = ctypes.c_int(0)
    ret = lib.EVP_DecryptFinal_ex(ctx, finalbuf_d, ctypes.byref(finallen_d))
    print("  DecryptFinal ret=%d (expected 1)" % ret)

    lib.EVP_CIPHER_CTX_free(ctx)
    lib.EVP_CIPHER_free(cipher)

    if ret == 1:
        decrypted = ptbuf.raw[:ptlen.value]
        match = decrypted == plaintext
        print("  decrypted matches: %s" % match)
        return match
    else:
        print("  [FAIL] tag verification failed")
        return False


# ── 测试矩阵 ──
print("=== SM4-GCM 调试 ===")
r1 = sm4_gcm_test("无 AAD", use_aad=False, use_cast=False)
r2 = sm4_gcm_test("有 AAD", use_aad=True, use_cast=False)
r3 = sm4_gcm_test("有 AAD + cast", use_aad=True, use_cast=True)

print("\n=== 结果 ===")
print("  无 AAD:          %s" % ("PASS" if r1 else "FAIL"))
print("  有 AAD:          %s" % ("PASS" if r2 else "FAIL"))
print("  有 AAD + cast:   %s" % ("PASS" if r3 else "FAIL"))
