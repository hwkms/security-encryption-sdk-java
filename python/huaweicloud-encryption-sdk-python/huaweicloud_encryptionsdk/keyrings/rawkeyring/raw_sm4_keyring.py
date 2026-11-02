import os
import logging

from huaweicloud_encryptionsdk.common.utils import serialize_context, byte_to_secret_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm

logger = logging.getLogger(__name__)

SM4_GCM_IV_LEN = 12
SM4_GCM_TAG_LEN = 16


class RawSM4Keyring(RawKeyring):

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            iv = os.urandom(SM4_GCM_IV_LEN)
            from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _algs, modes as _modes

            sm4_alg = _algs.SM4(key_bytes)
            gcm = _modes.GCM(iv)
            cipher = _Cipher(sm4_alg, gcm)
            encryptor = cipher.encryptor()
            aad = serialize_context(data_key_materials.encryption_contexts)
            if aad:
                encryptor.authenticate_additional_data(aad)
            original_data_key = data_key_materials.plaintext_data_key
            encrypted = encryptor.update(original_data_key) + encryptor.finalize()
            encrypted_with_tag = encrypted + encryptor.tag
            message = iv + encrypted_with_tag
            ciphertext_data_keys.append(CiphertextDataKey(data_key=message))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            data_key = ciphertext_data_key.data_key
            algo = data_key_materials.crypto_algorithm
            if algo is not None and len(data_key) < SM4_GCM_IV_LEN + SM4_GCM_TAG_LEN:
                raise ValueError("data key too short")
            iv = data_key[:SM4_GCM_IV_LEN]
            tag = data_key[-SM4_GCM_TAG_LEN:]
            ct = data_key[SM4_GCM_IV_LEN:-SM4_GCM_TAG_LEN]

            from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _algs, modes as _modes

            sm4_alg = _algs.SM4(key_bytes)
            gcm = _modes.GCM(iv, tag, min_tag_length=SM4_GCM_TAG_LEN)
            cipher = _Cipher(sm4_alg, gcm)
            decryptor = cipher.decryptor()
            aad = serialize_context(data_key_materials.encryption_contexts)
            if aad:
                decryptor.authenticate_additional_data(aad)
            decrypted = decryptor.update(ct) + decryptor.finalize()
            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "SM4"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawSM4Keyring")
        return False

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.symmetric_key
