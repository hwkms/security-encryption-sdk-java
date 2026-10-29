import os
import logging

from huaweicloud_encryptionsdk.common.utils import serialize_context, byte_to_secret_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm

logger = logging.getLogger(__name__)

AES_IV_LEN = 12
AES_TAG_LEN = 16


class RawAesKeyring(RawKeyring):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 检查华为 OpenSSL 是否可用，不可用则降级到 cryptography
        try:
            from huaweicloud_encryptionsdk._openssl import is_available
            self._use_openssl = is_available()
        except Exception:
            self._use_openssl = False

    def _crypto_aes_gcm_encrypt(self, key_bytes, iv, data, aad):
        """cryptography 降级实现：AES-GCM 加密"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv), backend=None)
        encryptor = cipher.encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)
        ct = encryptor.update(data) + encryptor.finalize()
        return ct, encryptor.tag

    def _crypto_aes_gcm_decrypt(self, key_bytes, iv, ct, tag, aad):
        """cryptography 降级实现：AES-GCM 解密"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(iv, tag), backend=None)
        decryptor = cipher.decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(ct) + decryptor.finalize()

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            iv = os.urandom(AES_IV_LEN)
            aad = serialize_context(data_key_materials.encryption_contexts)
            original_data_key = data_key_materials.plaintext_data_key

            if self._use_openssl:
                from huaweicloud_encryptionsdk._openssl import aes_gcm_encrypt
                ct, tag = aes_gcm_encrypt(key_bytes, iv, original_data_key, aad)
            else:
                ct, tag = self._crypto_aes_gcm_encrypt(key_bytes, iv, original_data_key, aad)

            encrypted_with_tag = ct + tag
            message = iv + encrypted_with_tag
            ciphertext_data_keys.append(CiphertextDataKey(data_key=message))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            data_key = ciphertext_data_key.data_key
            algo = data_key_materials.crypto_algorithm
            if algo is not None and len(data_key) < AES_IV_LEN + AES_TAG_LEN:
                raise ValueError("data key too short")
            iv = data_key[:AES_IV_LEN]
            tag = data_key[-AES_TAG_LEN:]
            ct = data_key[AES_IV_LEN:-AES_TAG_LEN]

            aad = serialize_context(data_key_materials.encryption_contexts)

            if self._use_openssl:
                from huaweicloud_encryptionsdk._openssl import aes_gcm_decrypt
                decrypted = aes_gcm_decrypt(key_bytes, iv, ct, tag, aad)
            else:
                decrypted = self._crypto_aes_gcm_decrypt(key_bytes, iv, ct, tag, aad)

            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "AES"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawAesKeyring")
        return False

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key
