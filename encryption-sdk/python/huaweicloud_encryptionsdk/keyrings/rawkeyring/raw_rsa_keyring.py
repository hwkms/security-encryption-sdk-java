import logging

from huaweicloud_encryptionsdk.common.utils import byte_to_secret_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials

logger = logging.getLogger(__name__)


class RawRSAKeyring(RawKeyring):

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            encrypted = self._rsa_encrypt(key_bytes, data_key_materials.plaintext_data_key)
            ciphertext_data_keys.append(CiphertextDataKey(data_key=encrypted))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            decrypted = self._rsa_decrypt(key_bytes, ciphertext_data_key.data_key)
            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "AES"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawRSAKeyring")
        return False

    @staticmethod
    def _rsa_encrypt(pub_der: bytes, plaintext: bytes) -> bytes:
        # 优先使用华为 OpenSSL
        try:
            from huaweicloud_encryptionsdk._openssl import is_available
            if is_available():
                from huaweicloud_encryptionsdk._openssl._evp_pkey import rsa_encrypt
                return rsa_encrypt(pub_der, plaintext)
        except ImportError:
            pass
        # 降级到 cryptography
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        public_key = serialization.load_der_public_key(pub_der)
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def _rsa_decrypt(priv_der: bytes, ciphertext: bytes) -> bytes:
        # 优先使用华为 OpenSSL
        try:
            from huaweicloud_encryptionsdk._openssl import is_available
            if is_available():
                from huaweicloud_encryptionsdk._openssl._evp_pkey import rsa_decrypt
                return rsa_decrypt(priv_der, ciphertext)
        except ImportError:
            pass
        # 降级到 cryptography
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization
        private_key = serialization.load_der_private_key(priv_der, password=None)
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.public_key

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.private_key
