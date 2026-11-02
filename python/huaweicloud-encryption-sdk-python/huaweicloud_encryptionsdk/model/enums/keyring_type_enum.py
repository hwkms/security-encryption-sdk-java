from enum import Enum


class KeyringTypeEnum(Enum):

    RAW_AES = "AES"
    RAW_SM2 = "SM2"
    RAW_RSA = "RSA"
    RAW_SM4_CBC = "SM4_CBC"
    RAW_SM4_GCM = "SM4_GCM"
    KMS_MULTI_REGION = "multi"
    KMS_DISCOVERY = "discovery"
    KMS_KEY_CAPSULE = "key_capsule"

    def __init__(self, type_value):
        self._type = type_value

    @property
    def type(self):
        return self._type

    @classmethod
    def get_raw_keyring_type(cls, type_str):
        for keyring_type in cls:
            if keyring_type.type.lower() == type_str.lower():
                return keyring_type
        return None
