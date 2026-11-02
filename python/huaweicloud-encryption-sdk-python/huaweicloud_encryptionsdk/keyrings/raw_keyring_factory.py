from huaweicloud_encryptionsdk.exception.errors import KeyringNotFoundException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.keyring_factory import KeyringFactory
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_aes_keyring import RawAesKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_rsa_keyring import RawRSAKeyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm2_keyring import RawSM2Keyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_keyring import RawSM4Keyring
from huaweicloud_encryptionsdk.keyrings.rawkeyring.raw_sm4_cbc_keyring import RawSM4CBCKeyring
from huaweicloud_encryptionsdk.model.enums.keyring_type_enum import KeyringTypeEnum


class RawKeyringFactory(KeyringFactory):

    def get_keyring(self, type: str):
        keyring_type_enum = KeyringTypeEnum.get_raw_keyring_type(type)
        if keyring_type_enum is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NOT_FOUND_EXCEPTION.message)
        if keyring_type_enum == KeyringTypeEnum.RAW_AES:
            return RawAesKeyring()
        elif keyring_type_enum == KeyringTypeEnum.RAW_RSA:
            return RawRSAKeyring()
        elif keyring_type_enum == KeyringTypeEnum.RAW_SM2:
            return RawSM2Keyring()
        elif keyring_type_enum == KeyringTypeEnum.RAW_SM4_GCM:
            return RawSM4Keyring()
        elif keyring_type_enum == KeyringTypeEnum.RAW_SM4_CBC:
            return RawSM4CBCKeyring()
        return None
