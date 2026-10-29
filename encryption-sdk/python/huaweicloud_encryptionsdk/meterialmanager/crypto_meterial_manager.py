from abc import ABC, abstractmethod
from typing import Optional

from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials


class CryptoMaterialManager(ABC):

    @abstractmethod
    def get_materials_for_encrypt(self, keyring, data_key_materials: DataKeyMaterials, plain_text_length: int) -> DataKeyMaterials:
        pass

    @abstractmethod
    def get_materials_for_decrypt(self, keyring, cipher_text: bytes) -> DataKeyMaterials:
        pass

    @abstractmethod
    def get_materials_for_stream_decrypt(self, keyring, input_stream) -> DataKeyMaterials:
        pass
