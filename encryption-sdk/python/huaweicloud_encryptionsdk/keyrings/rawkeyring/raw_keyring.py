import logging
from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

from huaweicloud_encryptionsdk.common.utils import is_empty
from huaweicloud_encryptionsdk.exception.errors import EncryptException, HuaweicloudException, KeyringNotMatchException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.keyring import Keyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials

logger = logging.getLogger(__name__)


class RawKeyring(Keyring):

    def __init__(self):
        self._private_key: list[bytes] = []
        self._public_key: list[bytes] = []
        self._symmetric_key: list[bytes] = []

    @property
    def private_key(self):
        return self._private_key

    def set_private_key(self, keys):
        if isinstance(keys, list):
            self._private_key.extend(keys)
        else:
            self._private_key.extend(keys)

    @property
    def public_key(self):
        return self._public_key

    def set_public_key(self, keys):
        if isinstance(keys, list):
            self._public_key.extend(keys)
        else:
            self._public_key.extend(keys)

    @property
    def symmetric_key(self):
        return self._symmetric_key

    def set_symmetric_key(self, keys):
        if isinstance(keys, list):
            self._symmetric_key.extend(keys)
        else:
            self._symmetric_key.extend(keys)

    @abstractmethod
    def get_decrypt_secret_key(self) -> list[bytes]:
        pass

    @abstractmethod
    def get_encrypt_secret_key(self) -> list[bytes]:
        pass

    @abstractmethod
    def real_encrypt(self, key_bytes: bytes, ciphertext_data_keys: list, data_key_materials: DataKeyMaterials):
        pass

    @abstractmethod
    def real_decrypt(self, key_bytes: bytes, ciphertext_data_key: CiphertextDataKey, data_key_materials: DataKeyMaterials) -> bool:
        pass

    def encrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        encrypt_secret_key = self.get_encrypt_secret_key()
        if is_empty(encrypt_secret_key):
            raise HuaweicloudException(ErrorMessage.MASTER_KEY_SHOULD_NOT_NULL.message)
        try:
            self._do_encrypt(data_key_materials, encrypt_secret_key)
        except Exception as e:
            raise EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.message, e)
        return data_key_materials

    def _do_encrypt(self, data_key_materials: DataKeyMaterials, master_secret_key: list[bytes]):
        ciphertext_data_keys = data_key_materials.ciphertext_data_keys
        with ThreadPoolExecutor() as executor:
            futures = []
            for key_bytes in master_secret_key:
                future = executor.submit(self._encrypt_with_key, key_bytes, ciphertext_data_keys, data_key_materials)
                futures.append(future)
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.warning("encrypt data key error by local master key: %s", e)
        if len(ciphertext_data_keys) <= 0:
            raise EncryptException(ErrorMessage.ENCRYPT_DATA_KEY_EXCEPTION.message)
        data_key_materials.ciphertext_data_keys = ciphertext_data_keys

    def _encrypt_with_key(self, key_bytes, ciphertext_data_keys, data_key_materials):
        self.real_encrypt(key_bytes, ciphertext_data_keys, data_key_materials)

    def decrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        decrypt_secret_key = self.get_decrypt_secret_key()
        if is_empty(decrypt_secret_key):
            raise HuaweicloudException(ErrorMessage.MASTER_KEY_SHOULD_NOT_NULL.message)
        self._do_decrypt(data_key_materials, decrypt_secret_key)
        if is_empty(data_key_materials.ciphertext_data_keys):
            raise KeyringNotMatchException(ErrorMessage.KEYRING_NOT_MATCH_EXCEPTION.message)
        return data_key_materials

    def _do_decrypt(self, data_key_materials: DataKeyMaterials, master_secret_key: list[bytes]):
        ciphertext_data_keys = data_key_materials.ciphertext_data_keys
        for key_bytes in master_secret_key:
            for ciphertext_data_key in ciphertext_data_keys:
                is_decrypted = self.real_decrypt(key_bytes, ciphertext_data_key, data_key_materials)
                if is_decrypted:
                    return
        raise KeyringNotMatchException(ErrorMessage.KEYRING_NOT_MATCH_EXCEPTION.message)
