from huaweicloud_encryptionsdk.exception.errors import KeyringNotFoundException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.keyring_factory import KeyringFactory
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_discovery_keyring import KMSDiscoveryKeyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_multi_region_keyring import KMSMultiRegionKeyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_key_capsule_keyring import KMSKeyCapsuleKeyring
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum


class KmsKeyringFactory(KeyringFactory):

    def get_keyring(self, type: str):
        keyring_type_enum = KeyringTypeEnum.get_raw_keyring_type(type)
        if keyring_type_enum is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NOT_FOUND_EXCEPTION.message)
        if keyring_type_enum == KeyringTypeEnum.KMS_DISCOVERY:
            return KMSDiscoveryKeyring()
        elif keyring_type_enum == KeyringTypeEnum.KMS_MULTI_REGION:
            return KMSMultiRegionKeyring()
        elif keyring_type_enum == KeyringTypeEnum.KMS_KEY_CAPSULE:
            return KMSKeyCapsuleKeyring()
        return None
