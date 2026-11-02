import os
import logging

from huaweicloud_encryptionsdk.common.utils import serialize_context, byte_to_secret_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm

logger = logging.getLogger(__name__)

SM4_CBC_IV_LEN = 16


class RawSM4CBCKeyring(RawKeyring):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # SM4-CBC 仅支持华为 OpenSSL，无降级方案
        try:
            from huaweicloud_encryptionsdk._openssl import is_available
            if not is_available():
                raise EncryptException(
                    ErrorMessage.ENCRYPT_EXCEPTION.message,
                    RuntimeError("SM4-CBC 需要华为 OpenSSL，但当前环境不可用（已降级到 cryptography，不支持国密算法）")
                )
        except ImportError:
            raise EncryptException(
                ErrorMessage.ENCRYPT_EXCEPTION.message,
                RuntimeError("无法导入 _openssl 模块，SM4-CBC 不可用")
            )

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            iv = os.urandom(SM4_CBC_IV_LEN)
            from huaweicloud_encryptionsdk._openssl import sm4_cbc_encrypt
            original_data_key = data_key_materials.plaintext_data_key
            encrypted = sm4_cbc_encrypt(key_bytes, iv, original_data_key)
            message = iv + encrypted
            ciphertext_data_keys.append(CiphertextDataKey(data_key=message))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            data_key = ciphertext_data_key.data_key
            algo = data_key_materials.crypto_algorithm
            if algo is not None and len(data_key) < SM4_CBC_IV_LEN:
                raise ValueError("data key too short")
            iv = data_key[:SM4_CBC_IV_LEN]
            ct = data_key[SM4_CBC_IV_LEN:]
            from huaweicloud_encryptionsdk._openssl import sm4_cbc_decrypt
            decrypted = sm4_cbc_decrypt(key_bytes, iv, ct)
            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "SM4"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawSM4CBCKeyring")
        return False

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key
