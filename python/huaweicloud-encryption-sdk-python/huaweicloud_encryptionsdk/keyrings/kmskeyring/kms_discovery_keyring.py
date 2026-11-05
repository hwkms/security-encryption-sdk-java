from huaweicloud_encryptionsdk.common.utils import is_empty
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig


class KMSDiscoveryKeyring(KMSKeyring):

    def do_decrypt(self, data_key_materials: DataKeyMaterials):
        self._prepare_key_id(data_key_materials)
        self.real_decrypt(data_key_materials)

    def _prepare_key_id(self, data_key_materials: DataKeyMaterials):
        kms_config_list = []
        huawei_config = self.huawei_config
        origin_kms_config_list = huawei_config.origin_kms_config_list
        if not origin_kms_config_list:
            huawei_config.origin_kms_config_list = huawei_config.kms_config_list
            origin_kms_config_list = huawei_config.origin_kms_config_list
        for ciphertext_data_key in data_key_materials.ciphertext_data_keys:
            if not self._check_discovery(ciphertext_data_key):
                raise HuaweicloudException(ErrorMessage.NOT_SUPPORT_DISCOVERY_DECRYPT.message)
            current_kms_config = None
            if origin_kms_config_list:
                for kms_config in origin_kms_config_list:
                    if ciphertext_data_key.region == kms_config.region:
                        current_kms_config = KMSConfig(
                            region=ciphertext_data_key.region,
                            key_id=ciphertext_data_key.key_id,
                            project_id=kms_config.project_id,
                            end_point=ciphertext_data_key.end_point
                        )
                        break
            if current_kms_config is None:
                current_kms_config = KMSConfig(
                    region=ciphertext_data_key.region,
                    key_id=ciphertext_data_key.key_id,
                    project_id=ciphertext_data_key.project_id,
                    end_point=ciphertext_data_key.end_point
                )
            kms_config_list.append(current_kms_config)
        huawei_config.kms_config_list = kms_config_list

    @staticmethod
    def _check_discovery(ciphertext_data_key):
        return (ciphertext_data_key.is_discovery()
                and not is_empty(ciphertext_data_key.key_id)
                and not is_empty(ciphertext_data_key.region)
                and not is_empty(ciphertext_data_key.project_id))
