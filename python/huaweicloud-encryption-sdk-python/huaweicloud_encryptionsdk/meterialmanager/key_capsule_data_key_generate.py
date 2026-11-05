from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.meterialmanager.data_key_generate import DataKeyGenerate
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.model.key_capsule import KeyCapsule
from huaweicloud_encryptionsdk.common.utils import is_empty, hex_to_bytes, get_capsule_kms_config


class KeyCapsuleDataKeyGenerate(DataKeyGenerate):

    def data_key_generate(self, huawei_config, data_key_materials) -> None:
        kms_config = get_capsule_kms_config(huawei_config.kms_config_list, huawei_config.key_capsule_config)
        response = self._create_key_capsule_by_kms(data_key_materials, huawei_config.key_capsule_config, huawei_config, kms_config)
        key_capsule = self._parse_key_capsule(response, huawei_config.key_capsule_config)
        plaintext_data_key = self._parse_plaintext_data_key(response)
        data_key_materials.key_capsule = key_capsule
        data_key_materials.plaintext_data_key = plaintext_data_key

    @staticmethod
    def _create_key_capsule_by_kms(data_key_materials, config, huawei_config, kms_config):
        try:
            from huaweicloud_encryptionsdk.kms.kms_http_client import KmsHttpClient
            from huaweicloud_encryptionsdk.kms.create_key_capsule_request import CreateKeyCapsuleRequest
            client = KmsHttpClient(huawei_config.get_ak(), huawei_config.get_sk(), kms_config, huawei_config.security_token)
            request = KeyCapsuleDataKeyGenerate._build_request_body(data_key_materials, config, huawei_config, kms_config)
            return client.post("/kms/datakey-capsule/create", request)
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.message, e)

    @staticmethod
    def _build_request_body(data_key_materials, config, huawei_config, kms_config):
        crypto_algorithm = huawei_config.crypto_algorithm
        if crypto_algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING:
            crypto_algorithm = CryptoAlgorithm.AES_128_GCM_NOPADDING
        from huaweicloud_encryptionsdk.kms.create_key_capsule_request import CreateKeyCapsuleRequest
        body = CreateKeyCapsuleRequest(
            key_id=kms_config.key_id,
            datakey_length=crypto_algorithm.datakey_length,
        )
        policy_id = data_key_materials.policy_id
        key_policy = data_key_materials.key_policy
        if policy_id is None and key_policy is None:
            policy_id = config.default_policy_id if config else None
            key_policy = config.default_key_policy if config else None
        if key_policy:
            body.key_policy = key_policy
        elif policy_id:
            body.policy_id = policy_id
        return body

    @staticmethod
    def _parse_key_capsule(response, config):
        return KeyCapsule(
            key_id=response.get("key_id"),
            datakey_capsule=response.get("datakey_capsule"),
            access_point_type=config.access_point_config.type if config and config.access_point_config else 0,
        )

    @staticmethod
    def _parse_plaintext_data_key(response):
        try:
            return hex_to_bytes(response.get("datakey", ""))
        except Exception as e:
            raise HuaweicloudException("Failed to parse plaintext data key", e)
