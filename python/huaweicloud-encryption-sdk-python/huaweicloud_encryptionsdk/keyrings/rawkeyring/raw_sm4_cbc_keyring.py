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

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            iv = os.urandom(SM4_CBC_IV_LEN)
            from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
            original_data_key = data_key_materials.plaintext_data_key
            padded = self._pkcs7_pad(original_data_key, 16)
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(key_bytes, SM4_ENCRYPT)
            encrypted = crypt_sm4.crypt_cbc(iv, padded)
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
            from gmssl.sm4 import CryptSM4, SM4_DECRYPT
            crypt_sm4 = CryptSM4()
            crypt_sm4.set_key(key_bytes, SM4_DECRYPT)
            decrypted = crypt_sm4.crypt_cbc(iv, ct)
            decrypted = self._pkcs7_unpad(decrypted)
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

    @staticmethod
    def _pkcs7_pad(data, block_size):
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(data):
        pad_len = data[-1]
        return data[:-pad_len]
