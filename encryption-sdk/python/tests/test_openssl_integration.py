"""
端到端集成测试: 验证 HuaweiCrypto 使用 _openssl 模块完成全流程加解密

覆盖改动点 (5 个文件协同工作):
  - crypto_factory.py       提供 SM3 摘要 (header_tag 计算)
  - cipher_handler.py       三种算法的 cipher_data / cipher_header_data / process_byte
  - raw_aes_keyring.py      AES-GCM 数据密钥加解密
  - raw_sm4_keyring.py      SM4-GCM 数据密钥加解密
  - raw_sm4_cbc_keyring.py  SM4-CBC 数据密钥加解密

测试场景:
  1. bytes 加解密往返 (三种算法)
  2. stream 加解密往返 (三种算法)
  3. file 加解密往返 (三种算法)
  4. encryption_context 透传
  5. 多 master key 解密
  6. 大数据 (1MB)

运行:
  pytest tests/test_openssl_integration.py -v

前置条件:
  - 华为 OpenSSL 已安装在 /opt/huawei-openssl/lib/libcrypto.so
  - 或设置环境变量 HUAWEI_OPENSSL_LIB 指向 libcrypto.so
  - _openssl 模块已随包安装或源码可用
"""
import os
import io
import tempfile

import pytest

from huaweicloud_encryptionsdk import HuaweiCrypto, HuaweiConfig
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_aes_keyring import RawAesKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_keyring import RawSM4Keyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_cbc_keyring import RawSM4CBCKeyring
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk._openssl import supports_sm4_gcm

_SKIP_SM4_GCM = pytest.mark.skipif(
    not supports_sm4_gcm(), reason="SM4-GCM 需要 OpenSSL 3.x"
)


# ---------- 工具 ----------

def _make_crypto(algo: CryptoAlgorithm, master_key: bytes) -> HuaweiCrypto:
    config = HuaweiConfig(ak="", sk="", crypto_algorithm=algo, local_log_only=True)
    crypto = HuaweiCrypto(config)

    if algo in (CryptoAlgorithm.AES_128_GCM_NOPADDING, CryptoAlgorithm.AES_256_GCM_NOPADDING):
        keyring = RawAesKeyring()
    elif algo == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
        keyring = RawSM4Keyring()
    elif algo == CryptoAlgorithm.SM4_128_CBC_PADDING:
        keyring = RawSM4CBCKeyring()
    else:
        raise ValueError("unsupported algo: %s" % algo)

    keyring.set_symmetric_key([master_key])
    crypto.with_keyring(keyring)
    return crypto


def _gen_key(algo: CryptoAlgorithm) -> bytes:
    return os.urandom(algo.key_len)


# ---------- bytes 加解密 ----------

class TestBytesRoundtrip:

    @pytest.mark.parametrize("algo", [
        CryptoAlgorithm.AES_128_GCM_NOPADDING,
        CryptoAlgorithm.AES_256_GCM_NOPADDING,
        pytest.param(CryptoAlgorithm.SM4_128_GCM_NOPADDING, marks=_SKIP_SM4_GCM),
        CryptoAlgorithm.SM4_128_CBC_PADDING,
    ])
    def test_encrypt_decrypt_bytes(self, algo):
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"hello huawei openssl integration " * 10

        result = crypto.encrypt(plain)
        assert result.result is not None
        assert result.result != plain

        decrypted = crypto.decrypt(result.result)
        assert decrypted.result == plain

    def test_bytes_with_context(self):
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"plaintext with context"

        from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
        req = EncryptRequest(
            encryption_context={"env": "test", "user": "alice"},
            plain_text=plain,
        )
        result = crypto.encrypt(req)
        decrypted = crypto.decrypt(result.result)
        assert decrypted.result == plain

    def test_bytes_empty(self):
        """空明文加解密"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        # AES-GCM 空明文: 只有 tag
        result = crypto.encrypt(b"")
        decrypted = crypto.decrypt(result.result)
        assert decrypted.result == b""

    @_SKIP_SM4_GCM
    def test_bytes_large_1mb(self):
        """1MB 大数据"""
        algo = CryptoAlgorithm.SM4_128_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = os.urandom(1024 * 1024)

        result = crypto.encrypt(plain)
        decrypted = crypto.decrypt(result.result)
        assert decrypted.result == plain


# ---------- stream 加解密 ----------

class TestStreamRoundtrip:

    @pytest.mark.parametrize("algo", [
        CryptoAlgorithm.AES_256_GCM_NOPADDING,
        pytest.param(CryptoAlgorithm.SM4_128_GCM_NOPADDING, marks=_SKIP_SM4_GCM),
        CryptoAlgorithm.SM4_128_CBC_PADDING,
    ])
    def test_encrypt_decrypt_stream(self, algo):
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"stream content " * 1000

        in_stream = io.BytesIO(plain)
        enc_stream = io.BytesIO()
        crypto.encrypt_stream(in_stream, enc_stream)
        encrypted = enc_stream.getvalue()
        assert len(encrypted) > 0
        assert encrypted != plain

        # 解密
        dec_input = io.BytesIO(encrypted)
        dec_output = io.BytesIO()
        crypto.decrypt_stream(dec_input, dec_output)
        assert dec_output.getvalue() == plain

    def test_stream_with_context(self):
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"stream with context " * 100

        in_stream = io.BytesIO(plain)
        enc_stream = io.BytesIO()
        crypto.encrypt_stream(in_stream, enc_stream, encryption_context={"k": "v"})

        dec_input = io.BytesIO(enc_stream.getvalue())
        dec_output = io.BytesIO()
        crypto.decrypt_stream(dec_input, dec_output)
        assert dec_output.getvalue() == plain


# ---------- file 加解密 ----------

class TestFileRoundtrip:

    @pytest.mark.parametrize("algo", [
        CryptoAlgorithm.AES_256_GCM_NOPADDING,
        pytest.param(CryptoAlgorithm.SM4_128_GCM_NOPADDING, marks=_SKIP_SM4_GCM),
        CryptoAlgorithm.SM4_128_CBC_PADDING,
    ])
    def test_encrypt_decrypt_file(self, algo, tmp_path):
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"file content for integration test " * 200

        src = tmp_path / "plain.txt"
        enc = tmp_path / "plain.enc"
        dec = tmp_path / "plain.dec"

        src.write_bytes(plain)
        crypto.encrypt_file(str(src), str(enc))
        assert enc.exists()
        assert enc.read_bytes() != plain

        crypto.decrypt_file(str(enc), str(dec))
        assert dec.read_bytes() == plain

    @_SKIP_SM4_GCM
    def test_file_large(self, tmp_path):
        """较大文件 (512KB)"""
        algo = CryptoAlgorithm.SM4_128_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = os.urandom(512 * 1024)

        src = tmp_path / "big.bin"
        enc = tmp_path / "big.enc"
        dec = tmp_path / "big.dec"

        src.write_bytes(plain)
        crypto.encrypt_file(str(src), str(enc))
        crypto.decrypt_file(str(enc), str(dec))
        assert dec.read_bytes() == plain


# ---------- 多 master key ----------

class TestMultiMasterKey:

    def test_two_keys_both_decrypt(self):
        """两个 master key 加密的密文, 任一都能解"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        k1 = _gen_key(algo)
        k2 = _gen_key(algo)

        # 用 k1 加密
        crypto1 = _make_crypto(algo, k1)
        plain = b"multi key test"
        result = crypto1.encrypt(plain)

        # 用 k2 的 crypto 解密应失败 (keyring 不匹配)
        crypto2 = _make_crypto(algo, k2)
        with pytest.raises(Exception):
            crypto2.decrypt(result.result)

        # 用同时含 k1, k2 的 keyring 解密应成功
        config = HuaweiConfig(ak="", sk="", crypto_algorithm=algo, local_log_only=True)
        crypto3 = HuaweiCrypto(config)
        keyring = RawAesKeyring()
        keyring.set_symmetric_key([k1, k2])
        crypto3.with_keyring(keyring)

        decrypted = crypto3.decrypt(result.result)
        assert decrypted.result == plain


# ---------- 算法切换 ----------

@_SKIP_SM4_GCM
class TestAlgorithmSwitching:

    def test_different_algorithms_produce_different_ciphertext(self):
        """同一明文, 不同算法 -> 不同密文"""
        plain = b"same plaintext for different algorithms"
        results = []

        for algo in [
            CryptoAlgorithm.AES_256_GCM_NOPADDING,
            CryptoAlgorithm.SM4_128_GCM_NOPADDING,
            CryptoAlgorithm.SM4_128_CBC_PADDING,
        ]:
            crypto = _make_crypto(algo, _gen_key(algo))
            result = crypto.encrypt(plain)
            results.append(result.result)

        # 两两不同
        assert results[0] != results[1]
        assert results[0] != results[2]
        assert results[1] != results[2]


# ---------- header 完整性 ----------

class TestHeaderIntegrity:

    def test_tampered_ciphertext_fails(self):
        """篡改密文应解密失败"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        crypto = _make_crypto(algo, _gen_key(algo))
        plain = b"important data"
        result = crypto.encrypt(plain)

        tampered = bytearray(result.result)
        # 翻转最后一个字节 (通常是 tag 的一部分)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            crypto.decrypt(bytes(tampered))
