"""
测试 _openssl 模块的 OpenSSL 1.1.x / 3.x 版本兼容性

覆盖:
  - 版本检测 (version, is_v3, _parse_version)
  - 能力检测 (supports_sm4_gcm, 结果缓存)
  - cipher 辅助方法 (fetch_cipher, free_cipher, cipher_block_size)
  - digest 辅助方法 (fetch_digest, free_digest, digest_size)
  - SM4-GCM 在 1.1.x 上抛明确错误
  - AES-GCM / SM3 / SM4-CBC 在 1.1.x/3.x 均正常工作

运行:
  pytest tests/test_openssl_version_compat.py -v
"""
import pytest

from huaweicloud_encryptionsdk._openssl import (
    get_libcrypto, supports_sm4_gcm, OpenSSLError,
    aes_gcm_encrypt, aes_gcm_decrypt,
    sm4_cbc_encrypt, sm4_cbc_decrypt,
    sm4_gcm_encrypt, sm4_gcm_decrypt,
    sm3, sha256,
)


# ---------- 版本检测 ----------

class TestVersionDetection:

    def test_version_string_contains_openssl(self):
        ver = get_libcrypto().version()
        assert "OpenSSL" in ver, "版本字符串应包含 'OpenSSL': %s" % ver

    def test_is_v3_returns_bool(self):
        assert isinstance(get_libcrypto().is_v3(), bool)

    def test_parse_version_returns_tuple(self):
        major, minor = get_libcrypto()._parse_version()
        assert isinstance(major, int)
        assert isinstance(minor, int)
        assert major >= 0
        assert minor >= 0

    def test_is_v3_consistent_with_version_string(self):
        lc = get_libcrypto()
        ver = lc.version()
        major, _ = lc._parse_version()
        assert lc.is_v3() == (major >= 3)


# ---------- 能力检测 ----------

class TestCapabilityDetection:

    def test_supports_sm4_gcm_returns_bool(self):
        assert isinstance(supports_sm4_gcm(), bool)

    def test_supports_sm4_gcm_cached(self):
        """二次调用应返回缓存值 (不重新 fetch)"""
        lc = get_libcrypto()
        first = lc.supports_sm4_gcm()
        # 缓存已设置
        assert lc._sm4_gcm_supported is not None
        second = lc.supports_sm4_gcm()
        assert first == second

    def test_supports_sm4_gcm_matches_is_v3(self):
        """1.1.x 不支持 SM4-GCM; 3.x 支持 (取决于编译选项)"""
        lc = get_libcrypto()
        if not lc.is_v3():
            assert supports_sm4_gcm() is False
        # 3.x 上 supports_sm4_gcm 可能为 True 或 False (取决于是否编译了 SM4)


# ---------- cipher 辅助方法 ----------

class TestCipherHelpers:

    def test_fetch_cipher_aes_128_gcm(self):
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"AES-128-GCM")
        assert cipher is not None and cipher != 0
        lc.free_cipher(cipher)  # 不应报错

    def test_fetch_cipher_aes_256_gcm(self):
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"AES-256-GCM")
        assert cipher is not None and cipher != 0
        lc.free_cipher(cipher)

    def test_fetch_cipher_invalid_name_returns_null(self):
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"INVALID-CIPHER-NAME")
        assert cipher is None or cipher == 0

    def test_free_cipher_null_is_noop(self):
        """free_cipher(None/0) 不应报错"""
        lc = get_libcrypto()
        lc.free_cipher(None)
        lc.free_cipher(0)

    def test_cipher_block_size_aes_gcm(self):
        """GCM 是流式模式, block_size 返回 1"""
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"AES-128-GCM")
        bs = lc.cipher_block_size(cipher)
        assert bs == 1, "AES-GCM block size 应为 1 (流式), got %d" % bs
        lc.free_cipher(cipher)

    def test_cipher_block_size_aes_cbc(self):
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"AES-128-CBC")
        if cipher:
            bs = lc.cipher_block_size(cipher)
            assert bs == 16, "AES-CBC block size 应为 16, got %d" % bs
            lc.free_cipher(cipher)

    def test_cipher_block_size_sm4_cbc(self):
        lc = get_libcrypto()
        cipher = lc.fetch_cipher(b"SM4-CBC")
        if cipher:
            bs = lc.cipher_block_size(cipher)
            assert bs == 16, "SM4 block size 应为 16, got %d" % bs
            lc.free_cipher(cipher)


# ---------- digest 辅助方法 ----------

class TestDigestHelpers:

    def test_fetch_digest_sha256(self):
        lc = get_libcrypto()
        md = lc.fetch_digest(b"SHA256")
        assert md is not None and md != 0
        lc.free_digest(md)

    def test_fetch_digest_sm3(self):
        lc = get_libcrypto()
        md = lc.fetch_digest(b"SM3")
        if md:
            lc.free_digest(md)

    def test_digest_size_sha256(self):
        lc = get_libcrypto()
        md = lc.fetch_digest(b"SHA256")
        size = lc.digest_size(md)
        assert size == 32, "SHA256 digest size 应为 32, got %d" % size
        lc.free_digest(md)

    def test_free_digest_null_is_noop(self):
        lc = get_libcrypto()
        lc.free_digest(None)
        lc.free_digest(0)


# ---------- AES-GCM (1.1.x/3.x 通用) ----------

class TestAesGcmCompat:

    def test_aes_gcm_roundtrip(self):
        key = b"\x01" * 32
        iv = b"\x02" * 12
        plain = b"aes gcm compatibility test"
        aad = b"associated data"

        ct, tag = aes_gcm_encrypt(key, iv, plain, aad)
        assert len(ct) == len(plain)
        assert len(tag) == 16

        pt = aes_gcm_decrypt(key, iv, ct, tag, aad)
        assert pt == plain

    def test_aes_128_gcm_roundtrip(self):
        key = b"\x01" * 16
        iv = b"\x02" * 12
        plain = b"aes-128-gcm"

        ct, tag = aes_gcm_encrypt(key, iv, plain)
        pt = aes_gcm_decrypt(key, iv, ct, tag)
        assert pt == plain


# ---------- SM3 (1.1.x/3.x 通用, 华为 OpenSSL) ----------

class TestSm3Compat:

    def test_sm3_known_vector(self):
        """SM3("abc") = 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0"""
        result = sm3(b"abc")
        expected = bytes.fromhex(
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )
        assert result == expected, "SM3('abc') 不匹配标准向量"

    def test_sm3_empty(self):
        result = sm3(b"")
        assert len(result) == 32

    def test_sha256_known_vector(self):
        result = sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        assert result == expected


# ---------- SM4-CBC (1.1.x/3.x 通用, 华为 OpenSSL) ----------

class TestSm4CbcCompat:

    def test_sm4_cbc_roundtrip(self):
        key = b"\x01" * 16
        iv = b"\x02" * 16
        plain = b"sm4 cbc compatibility test"

        ct = sm4_cbc_encrypt(key, iv, plain)
        # PKCS7 padding: 24 -> 32 字节
        assert len(ct) == 32

        pt = sm4_cbc_decrypt(key, iv, ct)
        assert pt == plain

    def test_sm4_cbc_block_aligned(self):
        key = b"\x03" * 16
        iv = b"\x04" * 16
        plain = b"a" * 16  # 1 block -> 2 blocks (padding)

        ct = sm4_cbc_encrypt(key, iv, plain)
        assert len(ct) == 32

        pt = sm4_cbc_decrypt(key, iv, ct)
        assert pt == plain


# ---------- SM4-GCM (仅 3.x) ----------

SKIP_SM4_GCM = pytest.mark.skipif(
    not supports_sm4_gcm(), reason="SM4-GCM 需要 OpenSSL 3.x"
)


@SKIP_SM4_GCM
class TestSm4GcmCompat:

    def test_sm4_gcm_roundtrip(self):
        key = b"\x01" * 16
        iv = b"\x02" * 12
        plain = b"sm4 gcm compatibility test"
        aad = b"auth data"

        ct, tag = sm4_gcm_encrypt(key, iv, plain, aad)
        assert len(ct) == len(plain)
        assert len(tag) == 16

        pt = sm4_gcm_decrypt(key, iv, ct, tag, aad)
        assert pt == plain

    def test_sm4_gcm_empty_plaintext(self):
        key = b"\x01" * 16
        iv = b"\x02" * 12

        ct, tag = sm4_gcm_encrypt(key, iv, b"")
        assert ct == b""
        assert len(tag) == 16

        pt = sm4_gcm_decrypt(key, iv, ct, tag)
        assert pt == b""


# ---------- SM4-GCM 错误处理 (1.1.x) ----------

class TestSm4GcmErrorOnLegacy:

    @pytest.mark.skipif(supports_sm4_gcm(), reason="仅在 1.1.x 上测试错误路径")
    def test_sm4_gcm_encrypt_raises_on_1_1_x(self):
        with pytest.raises(OpenSSLError) as exc_info:
            sm4_gcm_encrypt(b"\x01" * 16, b"\x02" * 12, b"test")
        assert "SM4-GCM" in str(exc_info.value)
        assert "3.1+" in str(exc_info.value)

    @pytest.mark.skipif(supports_sm4_gcm(), reason="仅在 1.1.x 上测试错误路径")
    def test_sm4_gcm_decrypt_raises_on_1_1_x(self):
        with pytest.raises(OpenSSLError) as exc_info:
            sm4_gcm_decrypt(b"\x01" * 16, b"\x02" * 12, b"fake_ct", b"\x00" * 16)
        assert "SM4-GCM" in str(exc_info.value)
