import logging

from huaweicloud_encryptionsdk.common.utils import is_empty, bytes_to_hex, hex_to_bytes, get_capsule_kms_config
from huaweicloud_encryptionsdk.exception.errors import HuaweicloudException, ErrorMessage
from huaweicloud_encryptionsdk.keyrings.kmskeyring.kms_keyring import KMSKeyring
from huaweicloud_encryptionsdk.model.ciphertext_data_key import CiphertextDataKey
from huaweicloud_encryptionsdk.model.data_key_materials import DataKeyMaterials
from huaweicloud_encryptionsdk.model.kms_config import KMSConfig

logger = logging.getLogger(__name__)


class KMSKeyCapsuleKeyring(KMSKeyring):

    def do_decrypt(self, data_key_materials: DataKeyMaterials):
        key_capsule = data_key_materials.key_capsule
        if key_capsule is None:
            raise HuaweicloudException("Key capsule is null")

        ciphertext_data_keys = data_key_materials.ciphertext_data_keys
        if ciphertext_data_keys is None or len(ciphertext_data_keys) == 0:
            raise HuaweicloudException(ErrorMessage.CIPHER_TEXT_DATA_KEY_NOT_NULL.message)
        ciphertext_data_key = ciphertext_data_keys[0]
        kms_config = self._get_kms_config(ciphertext_data_key)
        key_capsule.datakey_capsule = bytes_to_hex(ciphertext_data_key.data_key)

        huawei_config = self.huawei_config
        from huaweicloudsdkcore.auth.credentials import BasicCredentials
        auth = BasicCredentials(huawei_config.ak, huawei_config.sk, kms_config.project_id)
        if huawei_config.security_token:
            auth = auth.with_security_token(huawei_config.security_token)

        access_point_config = huawei_config.key_capsule_config.access_point_config
        from huaweicloud_encryptionsdk.proof.proof_info import ProofInfo
        proof_info = ProofInfo(
            type=key_capsule.access_point_type,
            encrypted_private_key=access_point_config.encrypted_private_key,
            private_key_decrypt_callback=access_point_config.private_key_decrypt_callback,
            key_capsule=key_capsule.datakey_capsule,
        )

        from huaweicloud_encryptionsdk.proof.proof_collector_factory import ProofCollectorFactory
        attestation_document = ProofCollectorFactory.collect(proof_info)

        plaintext_data_key = self._decrypt_key_capsule_by_kms(key_capsule, attestation_document, kms_config, auth)

        data_key_materials.plaintext_data_key = plaintext_data_key

    def _get_kms_config(self, ciphertext_data_key):
        return KMSConfig(
            region=ciphertext_data_key.region,
            key_id=ciphertext_data_key.key_id,
            project_id=ciphertext_data_key.project_id,
            end_point=ciphertext_data_key.end_point
        )

    def encrypt_data_key(self, data_key_materials: DataKeyMaterials) -> DataKeyMaterials:
        key_capsule_config = self.huawei_config.key_capsule_config
        kms_config = get_capsule_kms_config(self.huawei_config.kms_config_list, key_capsule_config)
        region = key_capsule_config.region
        key_id = kms_config.key_id
        project_id = kms_config.project_id
        endpoint = kms_config.end_point
        if not endpoint:
            try:
                from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
                kms_region = KmsRegion.value_of(key_capsule_config.region)
                endpoint = kms_region.endpoints[0]
            except Exception:
                endpoint = None
        if not endpoint:
            raise HuaweicloudException(ErrorMessage.END_POINT_NOT_NULL.message)
        ciphertext_data_keys = []
        try:
            cipher_data_key_bytes = hex_to_bytes(data_key_materials.key_capsule.datakey_capsule)
        except Exception as e:
            raise HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_CAPSULE_EXCEPTION.message, e)
        ciphertext_data_keys.append(CiphertextDataKey(
            data_key=cipher_data_key_bytes,
            kms_config=KMSConfig(region=region, key_id=key_id, project_id=project_id, end_point=endpoint)
        ))
        data_key_materials.ciphertext_data_keys = ciphertext_data_keys
        return data_key_materials

    def _decrypt_key_capsule_by_kms(self, key_capsule, attestation_document, kms_config, auth):
        try:
            from huaweicloud_encryptionsdk.kms.kms_http_client import KmsHttpClient
            client = KmsHttpClient(self.huawei_config.ak, self.huawei_config.sk, kms_config, self.huawei_config.security_token)
            from huaweicloud_encryptionsdk.kms.decrypt_key_capsule_request import DecryptKeyCapsuleRequest
            request_body = DecryptKeyCapsuleRequest(
                key_id=key_capsule.key_id,
                datakey_capsule=key_capsule.datakey_capsule,
                attestation_document=attestation_document
            )
            from huaweicloud_encryptionsdk.kms.decrypt_key_capsule_response import DecryptKeyCapsuleResponse
            response = client.post("/kms/datakey-capsule/decrypt", request_body, DecryptKeyCapsuleResponse)
            key_capsule.instance_id = response.instance_id
            return hex_to_bytes(response.datakey)
        except Exception as e:
            raise HuaweicloudException("Failed to decrypt key capsule", e)
