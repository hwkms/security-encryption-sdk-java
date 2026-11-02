from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials


class Keyring(ABC):

    @abstractmethod
    def encrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        pass

    @abstractmethod
    def decrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        pass
