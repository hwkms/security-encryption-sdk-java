import logging

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

from huaweicloud_encryptionsdk.common.utils import byte_to_secret_key, get_public_key, get_private_key
from huaweicloud_encryptionsdk.exception.errors import EncryptException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_keyring import RawKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials

logger = logging.getLogger(__name__)


class RawRSAKeyring(RawKeyring):

    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        try:
            public_key = serialization.load_der_public_key(key_bytes)
            encode_datakey = data_key_materials.plaintext_data_key
            encrypted = public_key.encrypt(
                encode_datakey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            ciphertext_data_keys.append(CiphertextDataKey(data_key=encrypted))
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)

    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        try:
            private_key = serialization.load_der_private_key(key_bytes, password=None)
            decrypted = private_key.decrypt(
                ciphertext_data_key.data_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            algo_name = data_key_materials.crypto_algorithm.get_algorithm_name() if data_key_materials.crypto_algorithm else "AES"
            data_key_materials.plaintext_data_key = byte_to_secret_key(decrypted, algo_name)
            return True
        except Exception:
            logger.warning("one master key may be not match when decrypt data key in RawRSAKeyring")
        return False

    def get_encrypt_secret_key(self) -> list[bytes]:
        return self.public_key

    def get_decrypt_secret_key(self) -> list[bytes]:
        return self.private_key
