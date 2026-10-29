"""
_openssl 模块验证测试
验证 Digest (SM3/SHA256) 和 Cipher (AES-GCM/SM4-GCM/SM4-CBC) 功能正确
"""
import os
import sys
import traceback

# 确保使用项目内的代码
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from huaweicloud_encryptionsdk._openssl import (
    get_libcrypto, OpenSSLError,
    Digest, sm3, sha256, new,
    aes_gcm_encrypt, aes_gcm_decrypt,
    sm4_gcm_encrypt, sm4_gcm_decrypt,
    sm4_cbc_encrypt, sm4_cbc_decrypt,
)


def test_library_load():
    print("\n=== 测试库加载 ===")
    lc = get_libcrypto()
    print("  OpenSSL 版本: %s" % lc.version())
    assert "3.5.4" in lc.version(), "应为华为 OpenSSL 3.5.4"
    print("[OK] 库加载")


def test_sm3():
    print("\n=== 测试 SM3 ===")
    # 测试1: 便捷函数
    data = b"hello sm3"
    result = sm3(data)
    print("  sm3('%s') = %s" % (data.decode(), result.hex()))
    assert len(result) == 32, "SM3 应为 32 字节"

    # 测试2: Digest 对象 (多次 update)
    d = Digest("SM3")
    d.update(b"hello ")
    d.update(b"sm3")
    result2 = d.digest()
    assert result == result2, "分次 update 结果应一致"
    print("  分次 update 结果一致")

    # 测试3: hexdigest
    d2 = Digest("SM3")
    d2.update(data)
    assert d2.hexdigest() == result.hex()
    print("[OK] SM3")


def test_sha256():
    print("\n=== 测试 SHA256 ===")
    data = b"hello sha256"
    result = sha256(data)
    print("  sha256('%s') = %s" % (data.decode(), result.hex()))
    assert len(result) == 32, "SHA256 应为 32 字节"

    # 对比 hashlib
    import hashlib
    expected = hashlib.sha256(data).digest()
    assert result == expected, "应与 hashlib 一致"
    print("  与 hashlib 结果一致")
    print("[OK] SHA256")


def test_aes_gcm():
    print("\n=== 测试 AES-128-GCM ===")
    key = os.urandom(16)
    iv = os.urandom(12)
    aad = b"auth data"
    plaintext = b"AES-GCM test payload!!"

    # 加密
    ct, tag = aes_gcm_encrypt(key, iv, plaintext, aad)
    print("  plaintext(%d) -> ciphertext(%d) + tag(%d)" % (len(plaintext), len(ct), len(tag)))
    assert len(ct) == len(plaintext), "GCM 密文长度应等于明文"
    assert len(tag) == 16

    # 解密
    pt = aes_gcm_decrypt(key, iv, ct, tag, aad)
    assert pt == plaintext, "解密结果应匹配"
    print("  解密匹配")

    # 无 AAD
    ct2, tag2 = aes_gcm_encrypt(key, iv, plaintext)
    pt2 = aes_gcm_decrypt(key, iv, ct2, tag2)
    assert pt2 == plaintext
    print("  无 AAD 也通过")
    print("[OK] AES-128-GCM")

    # AES-256-GCM
    print("\n=== 测试 AES-256-GCM ===")
    key256 = os.urandom(32)
    ct3, tag3 = aes_gcm_encrypt(key256, iv, plaintext, aad)
    pt3 = aes_gcm_decrypt(key256, iv, ct3, tag3, aad)
    assert pt3 == plaintext
    print("[OK] AES-256-GCM")


def test_sm4_gcm():
    print("\n=== 测试 SM4-GCM ===")
    key = os.urandom(16)
    iv = os.urandom(12)
    aad = b"sm4 gcm aad"
    plaintext = b"SM4-GCM test payload!!"

    # 加密
    ct, tag = sm4_gcm_encrypt(key, iv, plaintext, aad)
    print("  plaintext(%d) -> ciphertext(%d) + tag(%d)" % (len(plaintext), len(ct), len(tag)))
    assert len(ct) == len(plaintext)
    assert len(tag) == 16

    # 解密
    pt = sm4_gcm_decrypt(key, iv, ct, tag, aad)
    assert pt == plaintext, "解密结果应匹配"
    print("  解密匹配")

    # tag 验证失败应抛异常
    wrong_tag = b"\x00" * 16
    try:
        sm4_gcm_decrypt(key, iv, ct, wrong_tag, aad)
        assert False, "应抛出 tag 验证失败异常"
    except OpenSSLError:
        print("  错误 tag 正确抛出异常")
    print("[OK] SM4-GCM")


def test_sm4_cbc():
    print("\n=== 测试 SM4-CBC ===")
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"SM4-CBC test!!"  # 14 bytes, 需 padding 到 16

    # 加密
    ct = sm4_cbc_encrypt(key, iv, plaintext)
    print("  plaintext(%d) -> ciphertext(%d)" % (len(plaintext), len(ct)))
    assert len(ct) % 16 == 0, "CBC 密文应为 16 字节倍数"
    assert len(ct) == 16, "14 bytes + 2 padding = 16"

    # 解密
    pt = sm4_cbc_decrypt(key, iv, ct)
    assert pt == plaintext, "解密结果应匹配"
    print("  解密匹配")

    # 空明文
    ct_empty = sm4_cbc_encrypt(key, iv, b"")
    pt_empty = sm4_cbc_decrypt(key, iv, ct_empty)
    assert pt_empty == b""
    print("  空明文也通过")

    # 大数据
    big_data = os.urandom(1024 * 256)  # 256KB
    ct_big = sm4_cbc_encrypt(key, iv, big_data)
    pt_big = sm4_cbc_decrypt(key, iv, ct_big)
    assert pt_big == big_data
    print("  256KB 数据通过")
    print("[OK] SM4-CBC")


def main():
    print("=" * 50)
    print("_openssl 模块验证测试")
    print("=" * 50)

    tests = [
        ("库加载",     test_library_load),
        ("SM3",        test_sm3),
        ("SHA256",     test_sha256),
        ("AES-GCM",    test_aes_gcm),
        ("SM4-GCM",    test_sm4_gcm),
        ("SM4-CBC",    test_sm4_cbc),
    ]

    results = {}
    for name, func in tests:
        try:
            func(lib)
            results[name] = True
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

    return 0 if all_pass else 1


if __name__ == "__main__":
    # 需要先 import lib 变量给 test 函数用
    # 实际上 test 函数内部调用 get_libcrypto(), 不需要传 lib
    # 修正 main 中的调用
    tests = [
        ("库加载",     test_library_load),
        ("SM3",        test_sm3),
        ("SHA256",     test_sha256),
        ("AES-GCM",    test_aes_gcm),
        ("SM4-GCM",    test_sm4_gcm),
        ("SM4-CBC",    test_sm4_cbc),
    ]

    results = {}
    for name, func in tests:
        try:
            func()
            results[name] = True
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
        print("\n全部通过!")
    else:
        print("\n有测试失败")
    sys.exit(0 if all_pass else 1)
