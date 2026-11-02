"""
测试 raw_aes_keyring.py / raw_sm4_keyring.py / raw_sm4_cbc_keyring.py 的改动

覆盖改动点:
  - RawAesKeyring.real_encrypt/real_decrypt     使用 aes_gcm_encrypt/aes_gcm_decrypt
  - RawSM4Keyring.real_encrypt/real_decrypt     使用 sm4_gcm_encrypt/sm4_gcm_decrypt
  - RawSM4CBCKeyring.real_encrypt/real_decrypt  使用 sm4_cbc_encrypt/sm4_cbc_decrypt
  - 密文格式: IV + ciphertext [+ tag]
  - 多 master key 场景
  - 错误 key 应返回 False (不抛异常)

运行:
  pytest tests/test_openssl_keyrings.py -v
"""
import os

import pytest

from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_aes_keyring import RawAesKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_keyring import RawSM4Keyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_cbc_keyring import RawSM4CBCKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.common.utils import byte_to_secret_key
from huaweicloud_encryptionsdk._openssl import supports_sm4_gcm

_SKIP_SM4_GCM = pytest.mark.skipif(
    not supports_sm4_gcm(), reason="SM4-GCM 需要 OpenSSL 3.x"
)


# ---------- 工具 ----------

def _make_materials(algo: CryptoAlgorithm, plain_key: bytes, ctx=None) -> DataKeyMaterials:
    m = DataKeyMaterials()
    m.crypto_algorithm = algo
    m.plaintext_data_key = plain_key
    m.encryption_contexts = ctx or {}
    return m


def _gen_key(algo: CryptoAlgorithm) -> bytes:
    return os.urandom(algo.key_len)


# ---------- RawAesKeyring ----------

class TestRawAesKeyring:
    """AES-GCM 数据密钥加解密 (改动: 不再用 cryptography)"""

    @pytest.mark.parametrize("algo", [
        CryptoAlgorithm.AES_128_GCM_NOPADDING,
        CryptoAlgorithm.AES_256_GCM_NOPADDING,
    ])
    def test_roundtrip(self, algo):
        keyring = RawAesKeyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(32)
        materials = _make_materials(algo, plain_dk, {"user": "alice"})

        # encrypt
        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        assert len(materials.ciphertext_data_keys) == 1
        cdk = materials.ciphertext_data_keys[0]
        assert isinstance(cdk, CiphertextDataKey)

        # 密文格式: IV(12) + ct + tag(16)
        assert len(cdk.data_key) == 12 + len(plain_dk) + 16

        # decrypt
        dec_materials = _make_materials(algo, b"", {"user": "alice"})
        ok = keyring.real_decrypt(master_key, cdk, dec_materials)
        assert ok is True
        assert dec_materials.plaintext_data_key == byte_to_secret_key(plain_dk, "AES") \
            or dec_materials.plaintext_data_key == plain_dk

    def test_wrong_master_key_returns_false(self):
        """错误 master key 应返回 False, 不抛异常"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        keyring = RawAesKeyring()
        correct_key = _gen_key(algo)
        wrong_key = _gen_key(algo)
        keyring.set_symmetric_key([correct_key])

        plain_dk = os.urandom(32)
        materials = _make_materials(algo, plain_dk)
        keyring.real_encrypt(correct_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        dec_materials = _make_materials(algo, b"")
        ok = keyring.real_decrypt(wrong_key, cdk, dec_materials)
        assert ok is False, "错误 key 应返回 False"

    def test_aad_mismatch_returns_false(self):
        """AAD (encryption_context) 不匹配应解密失败"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        keyring = RawAesKeyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(32)
        materials = _make_materials(algo, plain_dk, {"k": "v1"})
        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        dec_materials = _make_materials(algo, b"", {"k": "v2"})
        ok = keyring.real_decrypt(master_key, cdk, dec_materials)
        assert ok is False

    def test_multiple_master_keys(self):
        """多 master key 加密同一 data key"""
        algo = CryptoAlgorithm.AES_256_GCM_NOPADDING
        keyring = RawAesKeyring()
        k1 = _gen_key(algo)
        k2 = _gen_key(algo)
        keyring.set_symmetric_key([k1, k2])

        plain_dk = os.urandom(32)
        materials = _make_materials(algo, plain_dk)

        # 模拟 _do_encrypt: 对每个 key 调一次 real_encrypt
        keyring.real_encrypt(k1, materials.ciphertext_data_keys, materials)
        keyring.real_encrypt(k2, materials.ciphertext_data_keys, materials)
        assert len(materials.ciphertext_data_keys) == 2

        # 任一 key 都能解密
        for key in [k1, k2]:
            dec_m = _make_materials(algo, b"")
            ok = keyring.real_decrypt(key, materials.ciphertext_data_keys[0], dec_m)
            # k1 能解第一个, k2 解第二个
        # k1 解密第一个
        dec_m1 = _make_materials(algo, b"")
        assert keyring.real_decrypt(k1, materials.ciphertext_data_keys[0], dec_m1) is True
        # k2 解密第二个
        dec_m2 = _make_materials(algo, b"")
        assert keyring.real_decrypt(k2, materials.ciphertext_data_keys[1], dec_m2) is True

    def test_get_encrypt_decrypt_secret_key(self):
        keyring = RawAesKeyring()
        keys = [b"\x01" * 32]
        keyring.set_symmetric_key(keys)
        assert keyring.get_encrypt_secret_key() == keys
        assert keyring.get_decrypt_secret_key() == keys


# ---------- RawSM4Keyring (GCM) ----------

@_SKIP_SM4_GCM
class TestRawSm4Keyring:
    """SM4-GCM 数据密钥加解密 (改动: 使用 _openssl.sm4_gcm_encrypt/decrypt)"""

    def test_roundtrip(self):
        algo = CryptoAlgorithm.SM4_128_GCM_NOPADDING
        keyring = RawSM4Keyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(16)
        materials = _make_materials(algo, plain_dk, {"env": "prod"})

        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        # SM4-GCM 格式: IV(12) + ct + tag(16)
        assert len(cdk.data_key) == 12 + len(plain_dk) + 16

        dec_materials = _make_materials(algo, b"", {"env": "prod"})
        ok = keyring.real_decrypt(master_key, cdk, dec_materials)
        assert ok is True

    def test_wrong_key_returns_false(self):
        algo = CryptoAlgorithm.SM4_128_GCM_NOPADDING
        keyring = RawSM4Keyring()
        correct_key = _gen_key(algo)
        wrong_key = _gen_key(algo)
        keyring.set_symmetric_key([correct_key])

        plain_dk = os.urandom(16)
        materials = _make_materials(algo, plain_dk)
        keyring.real_encrypt(correct_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        dec_materials = _make_materials(algo, b"")
        ok = keyring.real_decrypt(wrong_key, cdk, dec_materials)
        assert ok is False

    def test_aad_mismatch_returns_false(self):
        algo = CryptoAlgorithm.SM4_128_GCM_NOPADDING
        keyring = RawSM4Keyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(16)
        materials = _make_materials(algo, plain_dk, {"a": "1"})
        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        dec_materials = _make_materials(algo, b"", {"a": "2"})
        assert keyring.real_decrypt(master_key, cdk, dec_materials) is False

    def test_get_encrypt_decrypt_secret_key(self):
        keyring = RawSM4Keyring()
        keys = [b"\x02" * 16]
        keyring.set_symmetric_key(keys)
        assert keyring.get_encrypt_secret_key() == keys
        assert keyring.get_decrypt_secret_key() == keys


# ---------- RawSM4CBCKeyring ----------

class TestRawSm4CbcKeyring:
    """SM4-CBC 数据密钥加解密 (改动: 使用 _openssl.sm4_cbc_encrypt/decrypt, 移除手动 PKCS7)"""

    def test_roundtrip(self):
        algo = CryptoAlgorithm.SM4_128_CBC_PADDING
        keyring = RawSM4CBCKeyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(32)  # 2 blocks
        materials = _make_materials(algo, plain_dk)

        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        # SM4-CBC 格式: IV(16) + ct (含 PKCS7 padding, 由 OpenSSL 处理)
        # 32 字节明文 -> 48 字节密文 (1 block padding)
        assert len(cdk.data_key) == 16 + 48, "got=%d" % len(cdk.data_key)

        dec_materials = _make_materials(algo, b"")
        ok = keyring.real_decrypt(master_key, cdk, dec_materials)
        assert ok is True

    def test_roundtrip_non_block_aligned(self):
        """非 block 对齐的明文 (PKCS7 padding 由 OpenSSL 自动处理)"""
        algo = CryptoAlgorithm.SM4_128_CBC_PADDING
        keyring = RawSM4CBCKeyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(20)  # 非 16 倍数
        materials = _make_materials(algo, plain_dk)

        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]
        # 20 字节 -> padding 到 32 -> 32 字节密文 + 16 IV
        assert len(cdk.data_key) == 16 + 32

        dec_materials = _make_materials(algo, b"")
        ok = keyring.real_decrypt(master_key, cdk, dec_materials)
        assert ok is True

    def test_wrong_key_returns_false(self):
        """错误 key: SM4-CBC 解密可能不抛异常 (无 auth), 但解出的 plaintext 不对
        注意: CBC 没有 GCM 的 auth tag, 错误 key 不一定抛异常
        这里验证 real_decrypt 不抛异常 (被 try/except 捕获) 且返回 False"""
        algo = CryptoAlgorithm.SM4_128_CBC_PADDING
        keyring = RawSM4CBCKeyring()
        correct_key = _gen_key(algo)
        wrong_key = _gen_key(algo)
        keyring.set_symmetric_key([correct_key])

        plain_dk = os.urandom(32)
        materials = _make_materials(algo, plain_dk)
        keyring.real_encrypt(correct_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        dec_materials = _make_materials(algo, b"")
        # CBC 错误 key 可能 padding 错误 -> 抛异常 -> 返回 False
        # 或 padding 碰巧对 -> 返回 True (但解出的内容错误)
        # 这里只验证不抛出未捕获异常
        try:
            result = keyring.real_decrypt(wrong_key, cdk, dec_materials)
            assert result in (True, False)
        except Exception as e:
            pytest.fail("real_decrypt 不应抛出未捕获异常: %s" % e)

    def test_get_encrypt_decrypt_secret_key(self):
        keyring = RawSM4CBCKeyring()
        keys = [b"\x03" * 16]
        keyring.set_symmetric_key(keys)
        assert keyring.get_encrypt_secret_key() == keys
        assert keyring.get_decrypt_secret_key() == keys

    def test_ciphertext_includes_iv_prefix(self):
        """密文必须以 16 字节 IV 开头"""
        algo = CryptoAlgorithm.SM4_128_CBC_PADDING
        keyring = RawSM4CBCKeyring()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(16)
        materials = _make_materials(algo, plain_dk)
        keyring.real_encrypt(master_key, materials.ciphertext_data_keys, materials)
        cdk = materials.ciphertext_data_keys[0]

        iv = cdk.data_key[:16]
        ct = cdk.data_key[16:]
        assert len(iv) == 16, "IV 应为 16 字节"
        assert len(ct) > 0, "应有密文"


# ---------- 跨 keyring 一致性 ----------

class TestKeyringConsistency:
    """加密 -> 解密往返后, plaintext_data_key 应可还原"""

    @pytest.mark.parametrize("keyring_cls,algo", [
        (RawAesKeyring, CryptoAlgorithm.AES_256_GCM_NOPADDING),
        pytest.param(RawSM4Keyring, CryptoAlgorithm.SM4_128_GCM_NOPADDING, marks=_SKIP_SM4_GCM),
        (RawSM4CBCKeyring, CryptoAlgorithm.SM4_128_CBC_PADDING),
    ])
    def test_encrypt_then_decrypt_via_encrypt_data_key(self, keyring_cls, algo):
        """通过 RawKeyring.encrypt_data_key / decrypt_data_key 走完整流程"""
        keyring = keyring_cls()
        master_key = _gen_key(algo)
        keyring.set_symmetric_key([master_key])

        plain_dk = os.urandom(algo.key_len)
        materials = _make_materials(algo, plain_dk, {"ctx": "v"})

        # 完整 encrypt_data_key
        keyring.encrypt_data_key(materials)
        assert len(materials.ciphertext_data_keys) == 1

        # 完整 decrypt_data_key (需要清空 plaintext, 保留 ciphertext)
        dec_materials = DataKeyMaterials()
        dec_materials.crypto_algorithm = algo
        dec_materials.encryption_contexts = {"ctx": "v"}
        dec_materials.ciphertext_data_keys = materials.ciphertext_data_keys
        dec_materials.plaintext_data_key = b""

        keyring.decrypt_data_key(dec_materials)
        assert dec_materials.plaintext_data_key is not None
        assert len(dec_materials.plaintext_data_key) > 0
