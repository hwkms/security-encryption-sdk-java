from abc import ABC, abstractmethod

from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials


class DataKeyGenerate(ABC):

    @abstractmethod
    def data_key_generate(self, huawei_config, data_key_materials: DataKeyMaterials) -> None:
        pass
