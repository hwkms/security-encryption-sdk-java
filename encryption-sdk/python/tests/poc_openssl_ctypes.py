"""
POC: ctypes 调用华为 OpenSSL libcrypto.so
验证 SM3 / SM4-CBC / SM4-GCM / SM2 基本功能
"""
import ctypes
import ctypes.util
import os
import sys
import traceback

# ── 常量 ──────────────────────────────────────────────
EVP_CTRL_GCM_SET_IVLEN = 0x09
EVP_CTRL_GCM_GET_TAG   = 0x10
EVP_CTRL_GCM_SET_TAG   = 0x11

OPENSSL_SUCCESS = 1

# ── 加载 libcrypto ─────────────────────────────────────
def load_libcrypto():
    # 优先级: 环境变量 > /opt/huawei-openssl/* > 系统
    env_path = os.environ.get("HUAWEI_OPENSSL_LIB")
    candidates = []
    if env_path:
        candidates.append(env_path)
    # 搜索华为 OpenSSL 安装目录 (lib64 优先, 然后 lib)
    for subdir in ("lib64", "lib"):
        base = "/opt/huawei-openssl/" + subdir
        if os.path.isdir(base):
            for name in ("libcrypto.so.3", "libcrypto.so"):
                p = os.path.join(base, name)
                if os.path.exists(p):
                    candidates.append(p)

    print("候选库路径:")
    for c in candidates:
        print("  %s (exists=%s)" % (c, os.path.exists(c)))

    for p in candidates:
        try:
            lib = ctypes.CDLL(p)
            print("[OK] 加载 libcrypto: %s" % p)
            return lib
        except OSError as e:
            print("  加载 %s 失败: %s" % (p, e))

    # fallback: 系统路径
    path = ctypes.util.find_library("crypto")
    if path:
        lib = ctypes.CDLL(path)
        print("[WARN] 加载系统 libcrypto (非华为): %s" % path)
        return lib
    raise RuntimeError("找不到 libcrypto.so")


def setup_functions(lib):
    """设置 ctypes 函数签名"""

    # ── EVP_MD (摘要) ──
    lib.EVP_MD_fetch.restype = ctypes.c_void_p
    lib.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_MD_CTX_new.restype = ctypes.c_void_p
    lib.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_DigestInit_ex.restype = ctypes.c_int
    lib.EVP_DigestInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    lib.EVP_DigestUpdate.restype = ctypes.c_int
    lib.EVP_DigestUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

    lib.EVP_DigestFinal_ex.restype = ctypes.c_int
    lib.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]

    lib.EVP_MD_get_size.restype = ctypes.c_int
    lib.EVP_MD_get_size.argtypes = [ctypes.c_void_p]

    lib.EVP_MD_free.restype = None
    lib.EVP_MD_free.argtypes = [ctypes.c_void_p]

    # ── EVP_CIPHER (对称加密) ──
    lib.EVP_CIPHER_fetch.restype = ctypes.c_void_p
    lib.EVP_CIPHER_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_EncryptInit_ex.restype = ctypes.c_int
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_EncryptUpdate.restype = ctypes.c_int
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

    lib.EVP_DecryptInit_ex.restype = ctypes.c_int
    lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_char_p, ctypes.c_char_p]

    lib.EVP_DecryptUpdate.restype = ctypes.c_int
    lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]

    lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
    lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]

    lib.EVP_CIPHER_get_block_size.restype = ctypes.c_int
    lib.EVP_CIPHER_get_block_size.argtypes = [ctypes.c_void_p]

    lib.EVP_CIPHER_free.restype = None
    lib.EVP_CIPHER_free.argtypes = [ctypes.c_void_p]

    # ── OpenSSL 版本 ──
    lib.OpenSSL_version.restype = ctypes.c_char_p
    lib.OpenSSL_version.argtypes = [ctypes.c_int]


# ── 测试: SM3 ──────────────────────────────────────────
def test_sm3(lib):
    print("\n=== 测试 SM3 摘要 ===")
    md = lib.EVP_MD_fetch(None, b"SM3", None)
    if not md:
        print("[FAIL] EVP_MD_fetch(SM3) 返回 NULL")
        return False
    md_size = lib.EVP_MD_get_size(md)
    print("  SM3 digest size: %d bytes" % md_size)

    ctx = lib.EVP_MD_CTX_new()
    data = b"hello huawei openssl sm3 test"
    digest = ctypes.create_string_buffer(md_size)
    digest_len = ctypes.c_uint(0)

    assert lib.EVP_DigestInit_ex(ctx, md, None) == OPENSSL_SUCCESS
    assert lib.EVP_DigestUpdate(ctx, data, len(data)) == OPENSSL_SUCCESS
    assert lib.EVP_DigestFinal_ex(ctx, digest, ctypes.byref(digest_len)) == OPENSSL_SUCCESS

    hex_digest = digest.raw[:digest_len.value].hex()
    print("  SM3('%s') = %s" % (data.decode(), hex_digest))
    print("  digest length: %d bytes" % digest_len.value)

    lib.EVP_MD_CTX_free(ctx)
    lib.EVP_MD_free(md)
    print("[OK] SM3 测试通过")
    return True


# ── 测试: SM4-CBC ──────────────────────────────────────
def test_sm4_cbc(lib):
    print("\n=== 测试 SM4-CBC 加解密 ===")
    cipher = lib.EVP_CIPHER_fetch(None, b"SM4-CBC", None)
    if not cipher:
        print("[FAIL] EVP_CIPHER_fetch(SM4-CBC) 返回 NULL")
        return False

    block_size = lib.EVP_CIPHER_get_block_size(cipher)
    print("  SM4-CBC block size: %d" % block_size)

    key = os.urandom(16)  # SM4 key = 128 bit
    iv = os.urandom(16)   # SM4 IV = 128 bit
    plaintext = b"SM4-CBC encryption test!!!"  # 28 bytes, 需要 padding 到 32 bytes

    # ── 加密 ──
    ctx = lib.EVP_CIPHER_CTX_new()
    assert lib.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) == OPENSSL_SUCCESS

    outbuf = ctypes.create_string_buffer(len(plaintext) + block_size)
    outlen = ctypes.c_int(0)
    assert lib.EVP_EncryptUpdate(ctx, outbuf, ctypes.byref(outlen), plaintext, len(plaintext)) == OPENSSL_SUCCESS

    finalbuf = ctypes.create_string_buffer(block_size)
    finallen = ctypes.c_int(0)
    assert lib.EVP_EncryptFinal_ex(ctx, finalbuf, ctypes.byref(finallen)) == OPENSSL_SUCCESS

    ciphertext = outbuf.raw[:outlen.value] + finalbuf.raw[:finallen.value]
    print("  plaintext (%d bytes) -> ciphertext (%d bytes)" % (len(plaintext), len(ciphertext)))
    lib.EVP_CIPHER_CTX_free(ctx)

    # ── 解密 ──
    ctx = lib.EVP_CIPHER_CTX_new()
    assert lib.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) == OPENSSL_SUCCESS

    outbuf2 = ctypes.create_string_buffer(len(ciphertext) + block_size)
    outlen2 = ctypes.c_int(0)
    assert lib.EVP_DecryptUpdate(ctx, outbuf2, ctypes.byref(outlen2), ciphertext, len(ciphertext)) == OPENSSL_SUCCESS

    finalbuf2 = ctypes.create_string_buffer(block_size)
    finallen2 = ctypes.c_int(0)
    ret = lib.EVP_DecryptFinal_ex(ctx, finalbuf2, ctypes.byref(finallen2))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptFinal_ex 失败 (ret=%d), 可能是 padding 错误" % ret)
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    decrypted = outbuf2.raw[:outlen2.value] + finalbuf2.raw[:finallen2.value]
    lib.EVP_CIPHER_CTX_free(ctx)
    lib.EVP_CIPHER_free(cipher)

    if decrypted[:len(plaintext)] == plaintext:
        print("  decrypted -> plaintext (%d bytes): %s" % (len(plaintext), decrypted[:len(plaintext)]))
        print("[OK] SM4-CBC 测试通过")
        return True
    else:
        print("[FAIL] 解密结果不匹配!")
        print("  expected: %s" % plaintext)
        print("  got:      %s" % decrypted[:len(plaintext)])
        return False


# ── 测试: SM4-GCM ──────────────────────────────────────
def test_sm4_gcm(lib):
    print("\n=== 测试 SM4-GCM 加解密 ===")
    cipher = lib.EVP_CIPHER_fetch(None, b"SM4-GCM", None)
    if not cipher:
        print("[FAIL] EVP_CIPHER_fetch(SM4-GCM) 返回 NULL")
        return False
    print("  SM4-GCM cipher fetched OK")

    key = os.urandom(16)  # SM4 key = 128 bit
    iv = os.urandom(12)   # GCM IV = 96 bit
    aad = b"additional authenticated data"
    plaintext = b"SM4-GCM encryption test data!!"  # 32 bytes

    # ── 加密 ──
    ctx = lib.EVP_CIPHER_CTX_new()

    # 1. Init cipher (no key/iv yet)
    ret = lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_EncryptInit_ex (cipher) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 2. Set IV length
    ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_CIPHER_CTX_ctrl (SET_IVLEN) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 3. Set key + IV
    ret = lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_EncryptInit_ex (key/iv) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 4. AAD (输出缓冲区必须为 NULL, 否则会被当成明文加密)
    aad_outlen = ctypes.c_int(0)
    ret = lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(aad_outlen), aad, len(aad))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_EncryptUpdate (AAD) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 5. Encrypt plaintext
    ctbuf = ctypes.create_string_buffer(len(plaintext) + 16)
    ctlen = ctypes.c_int(0)
    ret = lib.EVP_EncryptUpdate(ctx, ctbuf, ctypes.byref(ctlen), plaintext, len(plaintext))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_EncryptUpdate (plaintext) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 6. Finalize
    finalbuf = ctypes.create_string_buffer(32)
    finallen = ctypes.c_int(0)
    ret = lib.EVP_EncryptFinal_ex(ctx, finalbuf, ctypes.byref(finallen))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_EncryptFinal_ex 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    ciphertext = ctbuf.raw[:ctlen.value] + finalbuf.raw[:finallen.value]

    # 7. Get tag (16 bytes)
    tag = ctypes.create_string_buffer(16)
    ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_CIPHER_CTX_ctrl (GET_TAG) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    lib.EVP_CIPHER_CTX_free(ctx)

    print("  plaintext (%d bytes) -> ciphertext (%d bytes) + tag (16 bytes)" % (len(plaintext), len(ciphertext)))

    # ── 解密 ──
    ctx = lib.EVP_CIPHER_CTX_new()

    # 1. Init cipher
    ret = lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptInit_ex (cipher) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 2. Set IV length
    ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_Decrypt CTX_ctrl (SET_IVLEN) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 3. Set key + IV
    ret = lib.EVP_DecryptInit_ex(ctx, None, None, key, iv)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptInit_ex (key/iv) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 4. AAD (输出缓冲区必须为 NULL)
    outlen_d = ctypes.c_int(0)
    ret = lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen_d), aad, len(aad))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptUpdate (AAD) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 5. Decrypt ciphertext
    ptbuf = ctypes.create_string_buffer(len(ciphertext) + 16)
    ptlen = ctypes.c_int(0)
    ret = lib.EVP_DecryptUpdate(ctx, ptbuf, ctypes.byref(ptlen), ciphertext, len(ciphertext))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptUpdate (ciphertext) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 6. Set expected tag BEFORE final
    ret = lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_CIPHER_CTX_ctrl (SET_TAG) 失败")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    # 7. Finalize (verifies tag)
    finalbuf_d = ctypes.create_string_buffer(32)
    finallen_d = ctypes.c_int(0)
    ret = lib.EVP_DecryptFinal_ex(ctx, finalbuf_d, ctypes.byref(finallen_d))
    if ret != OPENSSL_SUCCESS:
        print("[FAIL] EVP_DecryptFinal_ex 失败 (tag 验证失败?)")
        lib.EVP_CIPHER_CTX_free(ctx)
        lib.EVP_CIPHER_free(cipher)
        return False

    decrypted = ptbuf.raw[:ptlen.value] + finalbuf_d.raw[:finallen_d.value]
    lib.EVP_CIPHER_CTX_free(ctx)
    lib.EVP_CIPHER_free(cipher)

    if decrypted[:len(plaintext)] == plaintext:
        print("  decrypted -> plaintext (%d bytes): %s" % (len(plaintext), decrypted[:len(plaintext)]))
        print("[OK] SM4-GCM 测试通过")
        return True
    else:
        print("[FAIL] 解密结果不匹配!")
        print("  expected: %s" % plaintext)
        print("  got:      %s" % decrypted[:len(plaintext)])
        return False


# ── 测试: AES-128-GCM (对比验证) ───────────────────────
def test_aes_gcm(lib):
    print("\n=== 测试 AES-128-GCM 加解密 ===")
    cipher = lib.EVP_CIPHER_fetch(None, b"AES-128-GCM", None)
    if not cipher:
        print("[FAIL] EVP_CIPHER_fetch(AES-128-GCM) 返回 NULL")
        return False

    key = os.urandom(16)
    iv = os.urandom(12)
    plaintext = b"AES-128-GCM test data!!"

    # 加密
    ctx = lib.EVP_CIPHER_CTX_new()
    lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None)
    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    lib.EVP_EncryptInit_ex(ctx, None, None, key, iv)

    ctbuf = ctypes.create_string_buffer(len(plaintext) + 16)
    ctlen = ctypes.c_int(0)
    lib.EVP_EncryptUpdate(ctx, ctbuf, ctypes.byref(ctlen), plaintext, len(plaintext))

    finalbuf = ctypes.create_string_buffer(32)
    finallen = ctypes.c_int(0)
    lib.EVP_EncryptFinal_ex(ctx, finalbuf, ctypes.byref(finallen))
    ciphertext = ctbuf.raw[:ctlen.value] + finalbuf.raw[:finallen.value]

    tag = ctypes.create_string_buffer(16)
    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)
    lib.EVP_CIPHER_CTX_free(ctx)

    # 解密
    ctx = lib.EVP_CIPHER_CTX_new()
    lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None)
    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None)
    lib.EVP_DecryptInit_ex(ctx, None, None, key, iv)

    ptbuf = ctypes.create_string_buffer(len(ciphertext) + 16)
    ptlen = ctypes.c_int(0)
    lib.EVP_DecryptUpdate(ctx, ptbuf, ctypes.byref(ptlen), ciphertext, len(ciphertext))

    lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)

    finalbuf_d = ctypes.create_string_buffer(32)
    finallen_d = ctypes.c_int(0)
    ret = lib.EVP_DecryptFinal_ex(ctx, finalbuf_d, ctypes.byref(finallen_d))
    lib.EVP_CIPHER_CTX_free(ctx)
    lib.EVP_CIPHER_free(cipher)

    if ret != OPENSSL_SUCCESS:
        print("[FAIL] AES-GCM 解密 tag 验证失败")
        return False

    decrypted = ptbuf.raw[:ptlen.value] + finalbuf_d.raw[:finallen_d.value]

    if decrypted[:len(plaintext)] == plaintext:
        print("[OK] AES-128-GCM 测试通过")
        return True
    else:
        print("[FAIL] AES-GCM 解密结果不匹配")
        return False


# ── 主流程 ─────────────────────────────────────────────
def main():
    print("=" * 50)
    print("华为 OpenSSL ctypes POC 测试")
    print("=" * 50)

    lib = load_libcrypto()
    setup_functions(lib)

    version = lib.OpenSSL_version(0)
    print("OpenSSL 版本: %s" % version.decode())

    results = {}
    tests = [
        ("SM3",        test_sm3),
        ("SM4-CBC",    test_sm4_cbc),
        ("SM4-GCM",    test_sm4_gcm),
        ("AES-128-GCM", test_aes_gcm),
    ]

    for name, func in tests:
        try:
            results[name] = func(lib)
        except Exception as e:
            print("[FAIL] %s 异常: %s" % (name, e))
            traceback.print_exc()
            results[name] = False

    print("\n" + "=" * 50)
    print("测试结果汇总:")
    print("=" * 50)
    all_pass = True
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print("  %-15s %s" % (name, status))
        if not passed:
            all_pass = False

    if all_pass:
        print("\n全部通过! ctypes 方案可行。")
    else:
        print("\n有测试失败，需要排查。")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
