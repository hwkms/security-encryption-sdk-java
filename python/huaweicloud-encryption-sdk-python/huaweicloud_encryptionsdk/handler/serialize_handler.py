from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.model.data_materials import DataMaterials


class SerializeHandler(ABC):

    @abstractmethod
    def serialize(self, data_materials):
        pass

    @abstractmethod
    def deserialize(self, cipher_data):
        pass
