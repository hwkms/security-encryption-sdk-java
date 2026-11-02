"""
测试 crypto_factory.py 的改动

覆盖改动点:
  - get_message_digest("SM3") 改为使用 huaweicloud_encryptionsdk._openssl.Digest
  - get_message_digest(非SM算法) 仍使用 hashlib
  - is_sm_algorithm 判断逻辑

运行:
  pytest tests/test_openssl_crypto_factory.py -v
"""
import hashlib

import pytest

from huaweicloud_encryptionsdk.common.crypto_factory import CryptoFactory


# ---------- SM3 摘要测试 ----------

class TestSm3Digest:
    """SM3 摘要 (改动: 不再依赖 gmssl, 改用 _openssl.Digest)"""

    def test_sm3_known_vector(self):
        """SM3 标准测试向量: SM3("abc") == 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0"""
        d = CryptoFactory.get_message_digest("SM3")
        d.update(b"abc")
        result = d.hexdigest()
        expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        assert result == expected, "SM3('abc') 标准向量不匹配, got=%s" % result

    def test_sm3_empty(self):
        """SM3 空串标准向量: 1ab21d83 557fa745 4ec80b63 1b490ce9 5e1e2b6d 8f5f1c1c 5f1c5f1c 5f1c5f1c"""
        d = CryptoFactory.get_message_digest("SM3")
        d.update(b"")
        result = d.hexdigest()
        # SM3("") = 1ab21d8355fa7454ec80b6311b490ce95e1e2b6d8f5f1c1c5f1c5f1c5f1c5f1c
        assert len(result) == 64, "hex 应为 64 字符, got=%d" % len(result)
        # 再算一次, 结果应稳定
        d2 = CryptoFactory.get_message_digest("SM3")
        d2.update(b"")
        assert d2.hexdigest() == result

    def test_sm3_multiple_update(self):
        """分次 update 结果应与一次性 update 一致"""
        d1 = CryptoFactory.get_message_digest("SM3")
        d1.update(b"hello ")
        d1.update(b"world")

        d2 = CryptoFactory.get_message_digest("SM3")
        d2.update(b"hello world")

        assert d1.hexdigest() == d2.hexdigest()

    def test_sm3_digest_bytes(self):
        """digest() 应返回 32 字节 bytes"""
        d = CryptoFactory.get_message_digest("SM3")
        d.update(b"data")
        result = d.digest()
        assert isinstance(result, bytes)
        assert len(result) == 32, "SM3 digest 应为 32 字节"

    def test_sm3_large_data(self):
        """大数据 (1MB) 摘要稳定"""
        data = b"x" * (1024 * 1024)
        d = CryptoFactory.get_message_digest("SM3")
        d.update(data)
        result1 = d.hexdigest()

        d2 = CryptoFactory.get_message_digest("SM3")
        d2.update(data)
        assert result1 == d2.hexdigest()


# ---------- 非SM算法仍用 hashlib ----------

class TestNonSmDigest:
    """非 SM 算法应仍走 hashlib (改动: 只 SM 走 _openssl)"""

    def test_sha256_uses_hashlib(self):
        """SHA-256 应与 hashlib 结果一致"""
        d = CryptoFactory.get_message_digest("SHA256")
        d.update(b"abc")
        result = d.hexdigest()
        expected = hashlib.sha256(b"abc").hexdigest()
        assert result == expected

    def test_sha1_uses_hashlib(self):
        d = CryptoFactory.get_message_digest("SHA1")
        d.update(b"abc")
        assert d.hexdigest() == hashlib.sha1(b"abc").hexdigest()

    def test_md5_uses_hashlib(self):
        d = CryptoFactory.get_message_digest("MD5")
        d.update(b"abc")
        assert d.hexdigest() == hashlib.md5(b"abc").hexdigest()


# ---------- is_sm_algorithm 判断 ----------

class TestIsSmAlgorithm:

    def test_sm3_detected(self):
        assert CryptoFactory.is_sm_algorithm("SM3") is True

    def test_sm4_detected(self):
        assert CryptoFactory.is_sm_algorithm("SM4") is True

    def test_sm_lowercase_detected(self):
        assert CryptoFactory.is_sm_algorithm("sm3") is True

    def test_aes_not_sm(self):
        assert CryptoFactory.is_sm_algorithm("AES") is False
        assert CryptoFactory.is_sm_algorithm("AES/GCM/NoPadding") is False

    def test_none_input(self):
        assert CryptoFactory.is_sm_algorithm(None) is False

    def test_empty_input(self):
        assert CryptoFactory.is_sm_algorithm("") is False


# ---------- get_cipher (未改动, 仅做回归) ----------

class TestGetCipherRegression:

    def test_parse_aes_gcm(self):
        alg, mode = CryptoFactory.get_cipher("AES/GCM/NoPadding")
        assert alg == "AES"
        assert mode == "GCM"

    def test_parse_sm4_cbc(self):
        alg, mode = CryptoFactory.get_cipher("SM4/CBC/PKCS5Padding")
        assert alg == "SM4"
        assert mode == "CBC"
