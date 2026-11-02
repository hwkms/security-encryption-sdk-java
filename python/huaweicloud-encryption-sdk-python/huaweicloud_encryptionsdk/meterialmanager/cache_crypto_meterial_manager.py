import struct
import base64
import logging
from typing import Dict, List, Optional

from huaweicloud_encryptionsdk.meterialmanager.crypto_meterial_manager import CryptoMaterialManager
from huaweicloud_encryptionsdk.meterialmanager.default_crypto_meterials_manager import DefaultCryptoMaterialsManager
from huaweicloud_encryptionsdk.cache.data_key_cache import DataKeyCache, UsageStatus
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.key_capsule import KeyCapsule
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.common.constants import NUM_1
from huaweicloud_encryptionsdk.common.crypto_factory import CryptoFactory
from huaweicloud_encryptionsdk.common.utils import serialize_context
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage

logger = logging.getLogger(__name__)


class CacheCryptoMaterialsManager(CryptoMaterialManager):

    CACHE_ID_ALGORITHM_SHA = "SHA-256"
    CACHE_ID_ALGORITHM_SM3 = "SM3"
    DEFAULT_MESSAGE_LIMIT = 0x7FFFFFFF
    DEFAULT_BYTE_LIMIT = 0x7FFFFFFFFFFFFFFF

    def __init__(self, cache: DataKeyCache, huawei_config):
        self._cache = cache
        self._max_byte_limit = self.DEFAULT_BYTE_LIMIT
        self._max_message_limit = self.DEFAULT_MESSAGE_LIMIT
        self._huawei_config = huawei_config
        self._crypto_material_manager = DefaultCryptoMaterialsManager(huawei_config)

    @property
    def max_byte_limit(self) -> int:
        return self._max_byte_limit

    def set_survival_time(self, survival_time: int) -> "CacheCryptoMaterialsManager":
        if survival_time <= 0:
            raise HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.message)
        self._cache.set_survival_time(survival_time)
        return self

    def set_max_message_limit(self, max_message_limit: int) -> "CacheCryptoMaterialsManager":
        if max_message_limit <= 0:
            raise HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.message)
        self._max_message_limit = max_message_limit
        return self

    def set_max_byte_limit(self, max_byte_limit: int) -> "CacheCryptoMaterialsManager":
        if max_byte_limit <= 0:
            raise HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.message)
        self._max_byte_limit = max_byte_limit
        return self

    def get_materials_for_encrypt(self, keyring, data_key_materials: DataKeyMaterials, plain_text_length: int) -> DataKeyMaterials:
        cache_id = self._get_cache_id(data_key_materials)
        usage_status = UsageStatus(plain_text_length, NUM_1)
        entry_for_encrypt = self._cache.get_entry_for_encrypt(cache_id, usage_status)
        if entry_for_encrypt is not None:
            usage_status_new = entry_for_encrypt.get_usage_status()
            if self._check_exceed_limit(usage_status_new):
                logger.info("get encrypt dataKeyMaterials from cache success, cacheId %s", cache_id)
                return entry_for_encrypt.get_data_key_materials()
            logger.info("dataKeyMaterials of cacheId %s exceed message limit, generate data key again", cache_id)
            entry_for_encrypt.invalidate()
        logger.info("dataKeyMaterials of cacheId %s not exists or expired, generate data key again", cache_id)
        self._crypto_material_manager.get_materials_for_encrypt(keyring, data_key_materials, plain_text_length)
        self._cache.put_entry_for_encrypt(cache_id, data_key_materials, usage_status)
        return data_key_materials

    def get_materials_for_decrypt(self, keyring, cipher_text: bytes) -> DataKeyMaterials:
        from huaweicloud_encryptionsdk.handler.default_serialize_handler import DefaultSerializeHandler
        data_materials = DefaultSerializeHandler().deserialize(cipher_text)
        headers = data_materials.headers
        cache_id = self._get_cache_id_from_headers(
            headers.algorithm, headers.encryption_context,
            headers.ciphertext_data_keys, headers.key_capsule,
        )
        entry_for_decrypt = self._cache.get_entry_for_decrypt(cache_id)
        if entry_for_decrypt is not None:
            logger.info("get decrypt dataKeyMaterials from cache success, cacheId %s", cache_id)
            return entry_for_decrypt.get_data_key_materials()
        logger.info("dataKeyMaterials of cacheId %s not exists or expired, Re-decrypt the dataKey", cache_id)
        data_key_materials = DataKeyMaterials()
        data_key_materials.ciphertext_data_keys = headers.ciphertext_data_keys
        data_key_materials.crypto_algorithm = headers.algorithm
        data_key_materials.encryption_contexts = headers.encryption_context
        if headers.key_capsule is not None:
            data_key_materials.key_capsule = headers.key_capsule
        data_key_materials = keyring.decrypt_data_key(data_key_materials)
        self._cache.put_entry_for_decrypt(cache_id, data_key_materials)
        return data_key_materials

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
        cache_id = self._get_cache_id_from_headers(
            data_materials.headers.algorithm,
            data_materials.headers.encryption_context,
            data_materials.headers.ciphertext_data_keys,
            data_materials.headers.key_capsule,
        )
        entry_for_decrypt = self._cache.get_entry_for_decrypt(cache_id)
        if entry_for_decrypt is not None:
            logger.info("get decrypt dataKeyMaterials from cache success, cacheId %s", cache_id)
            return entry_for_decrypt.get_data_key_materials()
        logger.info("dataKeyMaterials of cacheId %s not exists or expired, Re-decrypt the dataKey", cache_id)
        data_key_materials = DataKeyMaterials()
        data_key_materials.ciphertext_data_keys = data_materials.headers.ciphertext_data_keys
        data_key_materials.crypto_algorithm = data_materials.headers.algorithm
        data_key_materials.encryption_contexts = data_materials.headers.encryption_context
        if data_materials.headers.key_capsule is not None:
            data_key_materials.key_capsule = data_materials.headers.key_capsule
        keyring.decrypt_data_key(data_key_materials)
        self._cache.put_entry_for_decrypt(cache_id, data_key_materials)
        return data_key_materials

    def _get_cache_id(self, data_key_materials: DataKeyMaterials) -> str:
        try:
            algorithm = data_key_materials.crypto_algorithm
            if algorithm in (CryptoAlgorithm.SM4_128_GCM_NOPADDING, CryptoAlgorithm.SM4_128_CBC_PADDING):
                digest = CryptoFactory.get_message_digest(self.CACHE_ID_ALGORITHM_SM3)
            else:
                digest = CryptoFactory.get_message_digest(self.CACHE_ID_ALGORITHM_SHA)
            self._digest_algorithm(algorithm, digest)
            bytes_ctx = serialize_context(data_key_materials.encryption_contexts)
            self._digest_context(digest, bytes_ctx)
            self._digest_key_capsule_from_config(digest, self._huawei_config, data_key_materials)
            return base64.b64encode(digest.digest()).decode("utf-8")
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.MESSAGE_DIGEST_ERROR.message, e)

    def _get_cache_id_from_headers(self, algorithm, encryption_context, ciphertext_data_keys, key_capsule) -> str:
        try:
            if algorithm in (CryptoAlgorithm.SM4_128_GCM_NOPADDING, CryptoAlgorithm.SM4_128_CBC_PADDING):
                digest = CryptoFactory.get_message_digest(self.CACHE_ID_ALGORITHM_SM3)
            else:
                digest = CryptoFactory.get_message_digest(self.CACHE_ID_ALGORITHM_SHA)
            self._digest_algorithm(algorithm, digest)
            bytes_ctx = serialize_context(encryption_context)
            self._digest_context(digest, bytes_ctx)
            self._digest_ciphertext_data_keys(digest, ciphertext_data_keys)
            self._digest_key_capsule(digest, key_capsule)
            return base64.b64encode(digest.digest()).decode("utf-8")
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.MESSAGE_DIGEST_ERROR.message, e)

    @staticmethod
    def _digest_context(digest, bytes_ctx: bytes) -> None:
        if len(bytes_ctx) == 0:
            digest.update(b'\x00')
        else:
            digest.update(bytes_ctx)

    @staticmethod
    def _digest_algorithm(algorithm, digest) -> None:
        if algorithm is None:
            digest.update(b'\x00')
        else:
            digest.update(b'\x01')
            digest.update(algorithm.key_spec.encode("utf-8"))

    def _check_exceed_limit(self, usage_status: UsageStatus) -> bool:
        return (usage_status.bytes_encrypt_count <= self._max_byte_limit
                and usage_status.message_encrypt_count <= self._max_message_limit)

    @staticmethod
    def _digest_ciphertext_data_keys(digest, ciphertext_data_keys) -> None:
        if ciphertext_data_keys is None:
            digest.update(b'\x00')
        else:
            digest.update(b'\x01')
            digest.update(bytes([len(ciphertext_data_keys)]))
            sorted_keys = sorted(ciphertext_data_keys, key=lambda k: k.data_key if hasattr(k, 'data_key') else b'')
            for cdk in sorted_keys:
                if hasattr(cdk, 'to_byte_array'):
                    digest.update(cdk.to_byte_array())
                elif hasattr(cdk, 'data_key'):
                    digest.update(cdk.data_key)

    @staticmethod
    def _digest_key_capsule(digest, key_capsule: Optional[KeyCapsule]) -> None:
        if key_capsule is None:
            digest.update(b'\x00')
        else:
            digest.update(b'\x01')
            if key_capsule.key_id is not None:
                digest.update(key_capsule.key_id.encode("utf-8"))
            if key_capsule.datakey_capsule is not None:
                digest.update(key_capsule.datakey_capsule.encode("utf-8"))
            digest.update(bytes([key_capsule.access_point_type]))

    @staticmethod
    def _digest_key_capsule_from_config(digest, huawei_config, data_key_materials: DataKeyMaterials) -> None:
        key_capsule_config = huawei_config.key_capsule_config if huawei_config else None
        if key_capsule_config is None:
            digest.update(b'\x00')
        else:
            digest.update(b'\x01')
            from huaweicloud_encryptionsdk.common.utils import get_capsule_kms_config
            kms_config = get_capsule_kms_config(huawei_config.kms_config_list, key_capsule_config)
            if kms_config and kms_config.key_id:
                digest.update(kms_config.key_id.encode("utf-8"))
            if data_key_materials.key_policy or data_key_materials.policy_id:
                if data_key_materials.key_policy:
                    digest.update(data_key_materials.key_policy.encode("utf-8"))
                elif data_key_materials.policy_id:
                    digest.update(data_key_materials.policy_id.encode("utf-8"))
            else:
                if key_capsule_config.default_key_policy:
                    digest.update(key_capsule_config.default_key_policy.encode("utf-8"))
                elif key_capsule_config.default_policy_id:
                    digest.update(key_capsule_config.default_policy_id.encode("utf-8"))
