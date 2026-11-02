import os

from huaweicloud_encryptionsdk.meterialmanager.data_key_generate import DataKeyGenerate
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.common.constants import KEY_SPEC_DELIMITER


class LocalDataKeyGenerate(DataKeyGenerate):

    def data_key_generate(self, huawei_config, data_key_materials) -> None:
        algorithm = huawei_config.crypto_algorithm
        key_len = algorithm.key_len
        data_key_materials.plaintext_data_key = os.urandom(key_len)
