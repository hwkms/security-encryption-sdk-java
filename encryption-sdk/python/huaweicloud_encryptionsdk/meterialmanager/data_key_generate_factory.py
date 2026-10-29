from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.meterialmanager.data_key_generate import DataKeyGenerate
from huaweicloud_encryptionsdk.meterialmanager.local_data_key_generate import LocalDataKeyGenerate
from huaweicloud_encryptionsdk.meterialmanager.kms_data_key_generate import KmsDataKeyGenerate
from huaweicloud_encryptionsdk.meterialmanager.key_capsule_data_key_generate import KeyCapsuleDataKeyGenerate
from huaweicloud_encryptionsdk.model.enums.data_key_generate_type import DataKeyGenerateType


class DataKeyGenerateFactory:

    @staticmethod
    def get_data_key_generate(data_key_generate_type: DataKeyGenerateType) -> DataKeyGenerate:
        if data_key_generate_type == DataKeyGenerateType.LOCAL_GENERATE:
            return LocalDataKeyGenerate()
        elif data_key_generate_type == DataKeyGenerateType.KMS_GENERATE:
            return KmsDataKeyGenerate()
        elif data_key_generate_type == DataKeyGenerateType.KEY_CAPSULE_GENERATE:
            return KeyCapsuleDataKeyGenerate()
        else:
            raise HuaweicloudException(ErrorMessage.DATA_KEY_GENERATE_EXCEPTION.message)
