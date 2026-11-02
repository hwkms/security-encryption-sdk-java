from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.meterialmanager.data_key_generate import DataKeyGenerate
from huaweicloud_encryptionsdk.model.enums.crypto_algorithm import CryptoAlgorithm
from huaweicloud_encryptionsdk.common.utils import is_empty, hex_to_bytes


class KmsDataKeyGenerate(DataKeyGenerate):

    def data_key_generate(self, huawei_config, data_key_materials) -> None:
        kms_config_list = huawei_config.kms_config_list
        if is_empty(kms_config_list):
            raise HuaweicloudException(ErrorMessage.CONFIG_NULL_ERROR.message)
        for kms_config in kms_config_list:
            response = self._create_data_key_by_kms(
                kms_config.region, kms_config.key_id, kms_config.end_point,
                huawei_config.ak, huawei_config.sk, kms_config.project_id,
                huawei_config.crypto_algorithm,
                huawei_config.security_token,
            )
            plaint_bytes = hex_to_bytes(response.get("plain_text", ""))
            data_key_materials.plaintext_data_key = plaint_bytes
            return

    @staticmethod
    def _create_data_key_by_kms(region_str, key_id, end_point, ak, sk, project_id, algorithm, security_token=None):
        try:
            from huaweicloudsdkcore.auth.credentials import BasicCredentials
            from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
            from huaweicloudsdkkms.v2.kms_client import KmsClient
            from huaweicloudsdkkms.v2.model.create_datakey_request import CreateDatakeyRequest
            from huaweicloudsdkkms.v2.model.create_datakey_request_body import CreateDatakeyRequestBody

            credentials = BasicCredentials(ak, sk, project_id)
            if security_token:
                credentials = credentials.with_security_token(security_token)
            if end_point:
                from huaweicloudsdkcore.region.region import Region
                region = Region(region_str, end_point)
            else:
                region = KmsRegion.value_of(region_str)
            client = (
                KmsClient.new_builder()
                .with_credentials(credentials)
                .with_region(region)
                .build()
            )
            request = CreateDatakeyRequest()
            key_spec = algorithm.key_spec
            if CryptoAlgorithm.SM4_128_GCM_NOPADDING.key_spec.lower() == key_spec.lower():
                key_spec = CryptoAlgorithm.AES_128_GCM_NOPADDING.key_spec
            body = CreateDatakeyRequestBody(
                datakey_length=str(algorithm.key_len * 8),
                key_id=key_id,
                key_spec=key_spec,
            )
            request.body = body
            response = client.create_datakey(request)
            return {
                "plain_text": response.plain_text,
                "cipher_text": response.cipher_text,
            }
        except HuaweicloudException:
            raise
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.message, e)
