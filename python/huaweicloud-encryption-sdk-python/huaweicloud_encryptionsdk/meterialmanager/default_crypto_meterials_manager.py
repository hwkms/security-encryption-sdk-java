import struct
from typing import Optional

from huaweicloud_encryptionsdk.meterialmanager.crypto_meterial_manager import CryptoMaterialManager
from huaweicloud_encryptionsdk.meterialmanager.data_key_generate_factory import DataKeyGenerateFactory
from huaweicloud_encryptionsdk.model.enums.data_key_generate_type import DataKeyGenerateType
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage


class DefaultCryptoMaterialsManager(CryptoMaterialManager):

    def __init__(self, huawei_config=None):
        self._huawei_config = huawei_config

    def get_materials_for_encrypt(self, keyring, data_key_materials: DataKeyMaterials, plain_text_length: int) -> DataKeyMaterials:
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_key_capsule_keyring import KMSKeyCapsuleKeyring
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
        if isinstance(keyring, KMSKeyCapsuleKeyring):
            data_key_generate = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.KEY_CAPSULE_GENERATE)
            if hasattr(keyring, 'set_huawei_config'):
                keyring.set_huawei_config(self._huawei_config)
        elif isinstance(keyring, KMSKeyring):
            data_key_generate = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.KMS_GENERATE)
            if hasattr(keyring, 'set_huawei_config'):
                keyring.set_huawei_config(self._huawei_config)
        else:
            data_key_generate = DataKeyGenerateFactory.get_data_key_generate(DataKeyGenerateType.LOCAL_GENERATE)
        data_key_generate.data_key_generate(self._huawei_config, data_key_materials)
        return keyring.encrypt_data_key(data_key_materials)

    def get_materials_for_decrypt(self, keyring, cipher_text: bytes) -> DataKeyMaterials:
        from huaweicloud_encryptionsdk.handler.default_serialize_handler import DefaultSerializeHandler
        data_key_materials = DataKeyMaterials()
        data_materials = DefaultSerializeHandler().deserialize(cipher_text)
        data_key_materials.ciphertext_data_keys = data_materials.headers.ciphertext_data_keys
        data_key_materials.crypto_algorithm = data_materials.headers.algorithm
        data_key_materials.encryption_contexts = data_materials.headers.encryption_context
        if data_materials.headers.key_capsule is not None:
            data_key_materials.key_capsule = data_materials.headers.key_capsule
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_key_capsule_keyring import KMSKeyCapsuleKeyring
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
        if isinstance(keyring, KMSKeyCapsuleKeyring) and hasattr(keyring, 'set_huawei_config'):
            keyring.set_huawei_config(self._huawei_config)
        elif isinstance(keyring, KMSKeyring) and hasattr(keyring, 'set_huawei_config'):
            keyring.set_huawei_config(self._huawei_config)
        return keyring.decrypt_data_key(data_key_materials)

    def get_materials_for_stream_decrypt(self, keyring, input_stream) -> DataKeyMaterials:
        from huaweicloud_encryptionsdk.handler.default_serialize_handler import DefaultSerializeHandler
        length_byte = input_stream.read(2)
        if len(length_byte) != 2:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        length = struct.unpack(">h", length_byte)[0]
        bytes_data = input_stream.read(length)
        if len(bytes_data) != length:
            raise HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.message)
        data_materials = DefaultSerializeHandler().deserialize(bytes_data)
        data_key_materials = DataKeyMaterials()
        data_key_materials.ciphertext_data_keys = data_materials.headers.ciphertext_data_keys
        data_key_materials.crypto_algorithm = data_materials.headers.algorithm
        data_key_materials.encryption_contexts = data_materials.headers.encryption_context
        if data_materials.headers.key_capsule is not None:
            data_key_materials.key_capsule = data_materials.headers.key_capsule
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_key_capsule_keyring import KMSKeyCapsuleKeyring
        from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
        if isinstance(keyring, KMSKeyCapsuleKeyring) and hasattr(keyring, 'set_huawei_config'):
            keyring.set_huawei_config(self._huawei_config)
        elif isinstance(keyring, KMSKeyring) and hasattr(keyring, 'set_huawei_config'):
            keyring.set_huawei_config(self._huawei_config)
        return keyring.decrypt_data_key(data_key_materials)
