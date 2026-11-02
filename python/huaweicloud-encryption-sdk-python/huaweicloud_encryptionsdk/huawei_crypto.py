from __future__ import annotations

import os
from typing import Optional, Union

from huaweicloud_encryptionsdk.exception.errors import (
    HuaweicloudException,
    KeyringNotFoundException,
    ErrorMessage,
)
from huaweicloud_encryptionsdk.handler.default_crypto_handler import DefaultCryptoHandler
from huaweicloud_encryptionsdk.keyrings.keyring import Keyring
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
from huaweicloud_encryptionsdk.log.log_reporter_manager import LogReporterManager
from huaweicloud_encryptionsdk.meterialmanager.cache_crypto_meterial_manager import CacheCryptoMaterialsManager
from huaweicloud_encryptionsdk.meterialmanager.crypto_meterial_manager import CryptoMaterialManager
from huaweicloud_encryptionsdk.meterialmanager.default_crypto_meterials_manager import DefaultCryptoMaterialsManager
from huaweicloud_encryptionsdk.model.crypto_result import CryptoResult
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.enums.access_point_type import AccessPointType
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.request.encrypt_request import EncryptRequest
from huaweicloud_encryptionsdk.common.ecs_metadata_service import EcsMetadataService


class HuaweiCrypto:

    def __init__(self, huawei_config):
        self._huawei_config = huawei_config
        if self._huawei_config.crypto_algorithm is None:
            self._huawei_config.crypto_algorithm = CryptoAlgorithm.AES_128_GCM_NOPADDING
        self._crypto_handler = DefaultCryptoHandler()
        self._crypto_materials_manager: CryptoMaterialManager = DefaultCryptoMaterialsManager(huawei_config)
        self._keyring: Optional[Keyring] = None
        self._log_reporter_manager = LogReporterManager()

        if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
            self._log_reporter_manager.init(huawei_config)

    def close(self) -> None:
        self._log_reporter_manager.shutdown()

    def with_crypto_material_manager(self, manager: CryptoMaterialManager) -> HuaweiCrypto:
        self._crypto_materials_manager = manager
        return self

    def with_keyring(self, keyring: Keyring) -> HuaweiCrypto:
        self._keyring = keyring
        if isinstance(keyring, KMSKeyring):
            keyring.huawei_config = self._huawei_config
        return self

    def encrypt(self, plain_text_or_request: Union[bytes, EncryptRequest]) -> CryptoResult[bytes]:
        if isinstance(plain_text_or_request, (bytes, bytearray)):
            request = EncryptRequest(encryption_context={}, plain_text=plain_text_or_request)
        else:
            request = plain_text_or_request

        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            data_key_materials = DataKeyMaterials()
            data_key_materials.encryption_contexts = request.encryption_context or {}
            data_key_materials.crypto_algorithm = self._huawei_config.crypto_algorithm
            data_key_materials.policy_id = request.policy_id
            data_key_materials.key_policy = request.key_policy

            if isinstance(self._crypto_materials_manager, CacheCryptoMaterialsManager):
                if self._crypto_materials_manager.max_byte_limit < len(request.plain_text):
                    raise HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.message)

            data_key_materials = self._crypto_materials_manager.get_materials_for_encrypt(
                self._keyring, data_key_materials, len(request.plain_text)
            )
            result = self._crypto_handler.encrypt(request, data_key_materials)

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    encrypt_data_bytes = len(request.plain_text)
                    encrypt_output_bytes = result.data_length
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = (
                        EcsMetadataService.get_ecs_instance_id()
                        if data_key_materials.key_capsule.access_point_type == AccessPointType.ECS.code
                        else None
                    )
                    self._log_reporter_manager.record_encrypt_log(
                        None, encrypt_data_bytes, None, encrypt_output_bytes,
                        key_id, access_point_type, instance_id
                    )

            return result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.message) from e

    def decrypt(self, cipher_text: bytes) -> CryptoResult[bytes]:
        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            data_key_materials = self._crypto_materials_manager.get_materials_for_decrypt(
                self._keyring, cipher_text
            )
            result = self._crypto_handler.decrypt(cipher_text, data_key_materials)

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    decrypt_data_bytes = len(cipher_text)
                    decrypt_output_bytes = len(result.result) if result.result is not None else 0
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = data_key_materials.key_capsule.instance_id
                    self._log_reporter_manager.record_decrypt_log(
                        None, decrypt_data_bytes, None, decrypt_output_bytes,
                        key_id, access_point_type, instance_id
                    )

            return result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.message) from e

    def encrypt_stream(self, input_stream, output_stream, encryption_context=None) -> CryptoResult:
        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            encrypt_data_bytes = 0
            try:
                pos = input_stream.tell()
                input_stream.seek(0, 2)
                encrypt_data_bytes = input_stream.tell()
                input_stream.seek(pos)
            except Exception:
                pass

            data_key_materials = DataKeyMaterials()
            data_key_materials.encryption_contexts = encryption_context if encryption_context is not None else {}
            data_key_materials.crypto_algorithm = self._huawei_config.crypto_algorithm

            if isinstance(self._crypto_materials_manager, CacheCryptoMaterialsManager):
                if self._crypto_materials_manager.max_byte_limit < encrypt_data_bytes:
                    raise HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.message)

            data_key_materials = self._crypto_materials_manager.get_materials_for_encrypt(
                self._keyring, data_key_materials, encrypt_data_bytes
            )
            crypto_result = self._crypto_handler.encrypt_stream(
                input_stream, output_stream, data_key_materials, encryption_context
            )

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = (
                        EcsMetadataService.get_ecs_instance_id()
                        if data_key_materials.key_capsule.access_point_type == AccessPointType.ECS.code
                        else None
                    )
                    self._log_reporter_manager.record_encrypt_log(
                        None, encrypt_data_bytes, None, crypto_result.data_length,
                        key_id, access_point_type, instance_id
                    )

            return crypto_result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.message) from e

    def decrypt_stream(self, input_stream, output_stream) -> CryptoResult:
        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            decrypt_data_bytes = 0
            try:
                pos = input_stream.tell()
                input_stream.seek(0, 2)
                decrypt_data_bytes = input_stream.tell()
                input_stream.seek(pos)
            except Exception:
                pass

            data_key_materials = self._crypto_materials_manager.get_materials_for_stream_decrypt(
                self._keyring, input_stream
            )
            crypto_result = self._crypto_handler.decrypt_stream(
                input_stream, output_stream, data_key_materials
            )

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = data_key_materials.key_capsule.instance_id
                    self._log_reporter_manager.record_decrypt_log(
                        None, decrypt_data_bytes, None, None,
                        key_id, access_point_type, instance_id
                    )

            return crypto_result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.message) from e

    def encrypt_file(self, source_file_path: str, target_file_path: str, encryption_context=None) -> CryptoResult:
        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            encrypt_data_bytes = os.path.getsize(source_file_path)

            data_key_materials = DataKeyMaterials()
            data_key_materials.encryption_contexts = encryption_context if encryption_context is not None else {}
            data_key_materials.crypto_algorithm = self._huawei_config.crypto_algorithm

            if isinstance(self._crypto_materials_manager, CacheCryptoMaterialsManager):
                if self._crypto_materials_manager.max_byte_limit < encrypt_data_bytes:
                    raise HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.message)

            data_key_materials = self._crypto_materials_manager.get_materials_for_encrypt(
                self._keyring, data_key_materials, encrypt_data_bytes
            )

            with open(source_file_path, "rb", buffering=1024 * 1024) as input_stream, \
                 open(target_file_path, "wb", buffering=1024 * 1024) as output_stream:
                crypto_result = self._crypto_handler.encrypt_stream(
                    input_stream, output_stream, data_key_materials, encryption_context
                )

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = (
                        EcsMetadataService.get_ecs_instance_id()
                        if data_key_materials.key_capsule.access_point_type == AccessPointType.ECS.code
                        else None
                    )
                    output_size = os.path.getsize(target_file_path)
                    self._log_reporter_manager.record_encrypt_log(
                        os.path.basename(source_file_path), encrypt_data_bytes,
                        os.path.basename(target_file_path), output_size,
                        key_id, access_point_type, instance_id
                    )

            return crypto_result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.message) from e

    def decrypt_file(self, source_file_path: str, target_file_path: str) -> CryptoResult:
        if self._keyring is None:
            raise KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.message)

        data_key_materials = None
        try:
            decrypt_data_bytes = os.path.getsize(source_file_path)

            with open(source_file_path, "rb", buffering=1024 * 1024) as input_stream:
                data_key_materials = self._crypto_materials_manager.get_materials_for_stream_decrypt(
                    self._keyring, input_stream
                )
                with open(target_file_path, "wb", buffering=1024 * 1024) as output_stream:
                    crypto_result = self._crypto_handler.decrypt_stream(
                        input_stream, output_stream, data_key_materials
                    )

            if self._huawei_config.log_config is not None or self._huawei_config.local_log_only:
                if data_key_materials.key_capsule is not None:
                    key_id = data_key_materials.key_capsule.key_id
                    access_point_type = AccessPointType.get_display_name_by_code(
                        data_key_materials.key_capsule.access_point_type
                    )
                    instance_id = data_key_materials.key_capsule.instance_id
                    output_size = os.path.getsize(target_file_path)
                    self._log_reporter_manager.record_decrypt_log(
                        os.path.basename(source_file_path), decrypt_data_bytes,
                        os.path.basename(target_file_path), output_size,
                        key_id, access_point_type, instance_id
                    )

            return crypto_result
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.message) from e
